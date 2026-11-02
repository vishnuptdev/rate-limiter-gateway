// ASP.NET Core (.NET 6+) middleware that asks RateGuard's check API for a
// decision before the endpoint runs. Single file; not compiled by CI.
//
// Usage (Program.cs):
//   builder.Services.AddHttpClient("rateguard", c =>
//   {
//       c.BaseAddress = new Uri(Environment.GetEnvironmentVariable("RATEGUARD_URL") ?? "http://localhost:8080");
//       c.Timeout = TimeSpan.FromMilliseconds(50);
//   });
//   ...
//   app.UseMiddleware<RateGuardMiddleware>();
//
// Set RATEGUARD_TOKEN to an API token with scope "check".
//
// Behaviour:
//   - Allowed: RateGuard's headers (RateLimit-*) are copied onto the response.
//   - Denied: responds 429 (401/404 for unauthorized/no_route decisions).
//   - Fail-open: any error, bad token or answer slower than 50 ms lets the
//     request through.
//   - The consumer key is read from X-API-Key. Behind a load balancer call
//     app.UseForwardedHeaders() first so RemoteIpAddress is the real client.

using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

public class RateGuardMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IHttpClientFactory _factory;
    private readonly ILogger<RateGuardMiddleware> _log;
    private readonly string? _token = Environment.GetEnvironmentVariable("RATEGUARD_TOKEN");

    public RateGuardMiddleware(RequestDelegate next, IHttpClientFactory factory, ILogger<RateGuardMiddleware> log)
    {
        _next = next;
        _factory = factory;
        _log = log;
    }

    public async Task InvokeAsync(HttpContext ctx)
    {
        JsonElement? decision = null;
        try
        {
            if (string.IsNullOrEmpty(_token)) throw new InvalidOperationException("RATEGUARD_TOKEN not set");
            var body = new
            {
                method = ctx.Request.Method,
                path = ctx.Request.Path.Value,
                host = ctx.Request.Host.Host,
                api_key = ctx.Request.Headers["X-API-Key"].FirstOrDefault(),
                ip = ctx.Connection.RemoteIpAddress?.ToString(),
                cost = 1,
            };
            using var req = new HttpRequestMessage(HttpMethod.Post, "/_rlg/v1/check") { Content = JsonContent.Create(body) };
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _token);
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ctx.RequestAborted);
            cts.CancelAfter(TimeSpan.FromMilliseconds(50));
            using var resp = await _factory.CreateClient("rateguard").SendAsync(req, cts.Token);
            resp.EnsureSuccessStatusCode();
            decision = await resp.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: cts.Token);
        }
        catch (Exception e)
        {
            _log.LogWarning("rateguard: check failed, failing open: {Message}", e.Message);
        }

        // decision "error" = limiter backend unavailable: fail open.
        if (decision is JsonElement e0 && e0.TryGetProperty("decision", out var dk) && dk.GetString() == "error")
            decision = null;

        if (decision is JsonElement d)
        {
            if (d.TryGetProperty("headers", out var headers))
                foreach (var h in headers.EnumerateObject())
                    ctx.Response.Headers[h.Name] = h.Value.GetString();

            var allowed = !d.TryGetProperty("allowed", out var a) || a.GetBoolean();
            if (!allowed)
            {
                var kind = d.TryGetProperty("decision", out var k) ? k.GetString() : "limited";
                ctx.Response.StatusCode = kind == "unauthorized" ? 401 : kind == "no_route" ? 404 : 429;
                await ctx.Response.WriteAsJsonAsync(new { error = kind == "limited" ? "rate_limited" : kind });
                return;
            }
        }
        await _next(ctx);
    }
}
