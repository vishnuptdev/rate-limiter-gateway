# Rack middleware that asks RateGuard's check API for a decision before the app
# runs (works in Rails, Sinatra, Hanami, anything on Rack). Single file, only the
# Ruby standard library; not compiled by CI.
#
# Usage:
#   # config.ru
#   require_relative 'rate_guard'
#   use RateGuard, url: ENV.fetch('RATEGUARD_URL', 'http://localhost:8080'),
#                  token: ENV.fetch('RATEGUARD_TOKEN')   # API token, scope "check"
#   run MyApp
#   # Rails: config.middleware.use RateGuard, url: ..., token: ...
#
# Behaviour:
#   - Allowed: RateGuard's headers (RateLimit-*) are copied onto the response.
#   - Denied: responds 429 (401/404 for unauthorized/no_route decisions).
#   - Fail-open: any error, bad token or answer slower than 50 ms lets the
#     request through.
#   - The consumer key is read from X-API-Key. Behind a load balancer make sure
#     Rack's request.ip is the real client (e.g. Rails' trusted proxies).

require 'json'
require 'net/http'
require 'rack'
require 'uri'

class RateGuard
  TIMEOUT = 0.05 # seconds

  def initialize(app, url: 'http://localhost:8080', token: nil, timeout: TIMEOUT)
    @app = app
    @uri = URI.join(url.end_with?('/') ? url : "#{url}/", '_rlg/v1/check')
    @token = token
    @timeout = timeout
  end

  def call(env)
    decision = check(Rack::Request.new(env))
    return @app.call(env) if decision.nil?

    headers = decision['headers'] || {}
    unless decision['allowed'] == false
      status, resp_headers, body = @app.call(env)
      return [status, resp_headers.merge(headers), body]
    end

    code = { 'unauthorized' => 401, 'no_route' => 404 }.fetch(decision['decision'], 429)
    error = code == 429 ? 'rate_limited' : decision['decision']
    [code, headers.merge('Content-Type' => 'application/json'), [JSON.generate(error: error)]]
  end

  private

  def check(req)
    raise 'token not set' if @token.nil? || @token.empty?

    http = Net::HTTP.new(@uri.host, @uri.port)
    http.use_ssl = @uri.scheme == 'https'
    http.open_timeout = http.read_timeout = http.write_timeout = @timeout
    post = Net::HTTP::Post.new(@uri.request_uri,
                               'Content-Type' => 'application/json',
                               'Authorization' => "Bearer #{@token}")
    post.body = JSON.generate(
      method: req.request_method, path: req.path, host: req.host,
      api_key: req.get_header('HTTP_X_API_KEY'), ip: req.ip, cost: 1
    )
    resp = http.request(post)
    raise "check API returned HTTP #{resp.code}" unless resp.code == '200'

    JSON.parse(resp.body)
  rescue StandardError => e
    warn "rateguard: check failed, failing open: #{e.message}"
    nil
  end
end
