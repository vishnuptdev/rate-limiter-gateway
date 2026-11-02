<?php
// PSR-15 middleware that asks RateGuard's check API for a decision before the
// handler runs (Slim 4, Mezzio, Laminas, any PSR-15 stack). Single file; not
// compiled by CI.
//
// Requires: psr/http-server-middleware, psr/http-factory and the ext-curl
// extension (no HTTP client library needed).
//
// Usage (Slim 4 example):
//   $app->add(new RateGuardMiddleware(
//       getenv('RATEGUARD_URL') ?: 'http://localhost:8080',
//       getenv('RATEGUARD_TOKEN'),          // API token with scope "check"
//       $app->getResponseFactory(),
//   ));
//
// Behaviour:
//   - Allowed: RateGuard's headers (RateLimit-*) are copied onto the response.
//   - Denied: responds 429 (401/404 for unauthorized/no_route decisions).
//   - Fail-open: any error, bad token or answer slower than 50 ms lets the
//     request through.
//   - The consumer key is read from X-API-Key. The client IP is REMOTE_ADDR
//     from server params; behind a load balancer resolve it yourself first.

declare(strict_types=1);

use Psr\Http\Message\ResponseFactoryInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

final class RateGuardMiddleware implements MiddlewareInterface
{
    private const TIMEOUT_MS = 50;

    public function __construct(
        private string $baseUrl,
        private ?string $token,
        private ResponseFactoryInterface $responses,
    ) {
        $this->baseUrl = rtrim($baseUrl, '/');
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $decision = $this->check($request);
        if ($decision === null) {
            return $handler->handle($request); // fail open
        }
        $headers = is_array($decision['headers'] ?? null) ? $decision['headers'] : [];

        if (($decision['allowed'] ?? true) === false) {
            $kind = $decision['decision'] ?? 'limited';
            $status = match ($kind) {
                'unauthorized' => 401,
                'no_route' => 404,
                default => 429,
            };
            $response = $this->responses->createResponse($status)->withHeader('Content-Type', 'application/json');
            $response->getBody()->write(json_encode(['error' => $kind === 'limited' ? 'rate_limited' : $kind]));
        } else {
            $response = $handler->handle($request);
        }
        foreach ($headers as $name => $value) {
            $response = $response->withHeader((string) $name, (string) $value);
        }
        return $response;
    }

    private function check(ServerRequestInterface $request): ?array
    {
        try {
            if ($this->token === null || $this->token === '') {
                throw new RuntimeException('RATEGUARD_TOKEN not set');
            }
            $uri = $request->getUri();
            $body = json_encode([
                'method' => $request->getMethod(),
                'path' => $uri->getPath() ?: '/',
                'host' => $uri->getHost(),
                'api_key' => $request->getHeaderLine('X-API-Key') ?: null,
                'ip' => $request->getServerParams()['REMOTE_ADDR'] ?? null,
                'cost' => 1,
            ]);
            $ch = curl_init($this->baseUrl . '/_rlg/v1/check');
            curl_setopt_array($ch, [
                CURLOPT_POST => true,
                CURLOPT_POSTFIELDS => $body,
                CURLOPT_HTTPHEADER => ['Content-Type: application/json', 'Authorization: Bearer ' . $this->token],
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT_MS => self::TIMEOUT_MS,
                CURLOPT_CONNECTTIMEOUT_MS => self::TIMEOUT_MS,
                CURLOPT_NOSIGNAL => 1, // required for sub-second timeouts on some platforms
            ]);
            $out = curl_exec($ch);
            $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            if ($out === false || $code !== 200) {
                throw new RuntimeException($out === false ? curl_error($ch) : "check API returned HTTP $code");
            }
            $decision = json_decode($out, true, 16, JSON_THROW_ON_ERROR);
            return is_array($decision) ? $decision : null;
        } catch (Throwable $e) {
            error_log('rateguard: check failed, failing open: ' . $e->getMessage());
            return null;
        }
    }
}
