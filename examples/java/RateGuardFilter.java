// Spring (Boot 3 / Jakarta Servlet 6) filter that asks RateGuard's check API for
// a decision before the controller runs. Single file; not compiled by CI.
//
// Usage:
//   1. Copy this file into your project. It is a @Component, so Spring Boot
//      registers it for every request automatically.
//   2. Set RATEGUARD_URL (default http://localhost:8080) and RATEGUARD_TOKEN
//      (an API token with scope "check") in the environment.
//   3. Jackson (spring-boot-starter-web) is used for JSON; no other dependency.
//
// Behaviour:
//   - Allowed: RateGuard's headers (RateLimit-*) are copied onto the response.
//   - Denied: responds 429 with those headers (including Retry-After).
//   - Fail-open: any error, bad token or answer slower than 50 ms lets the
//     request through.
//   - The consumer key is read from X-API-Key. Behind a load balancer configure
//     server.forward-headers-strategy so getRemoteAddr() is the real client.

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class RateGuardFilter extends OncePerRequestFilter {
    private static final Duration TIMEOUT = Duration.ofMillis(50);
    private static final ObjectMapper JSON = new ObjectMapper();

    private final HttpClient client = HttpClient.newBuilder().connectTimeout(TIMEOUT).build();
    private final String checkUrl =
            System.getenv().getOrDefault("RATEGUARD_URL", "http://localhost:8080") + "/_rlg/v1/check";
    private final String token = System.getenv("RATEGUARD_TOKEN");

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
            throws ServletException, IOException {
        JsonNode decision = null;
        try {
            if (token == null || token.isBlank()) {
                throw new IllegalStateException("RATEGUARD_TOKEN not set");
            }
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("method", req.getMethod());
            body.put("path", req.getRequestURI());
            body.put("host", req.getServerName());
            body.put("api_key", req.getHeader("X-API-Key"));
            body.put("ip", req.getRemoteAddr());
            body.put("cost", 1);
            HttpRequest r = HttpRequest.newBuilder(URI.create(checkUrl))
                    .timeout(TIMEOUT)
                    .header("Content-Type", "application/json")
                    .header("Authorization", "Bearer " + token)
                    .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body)))
                    .build();
            HttpResponse<String> resp = client.send(r, HttpResponse.BodyHandlers.ofString());
            if (resp.statusCode() != 200) {
                throw new IllegalStateException("check API returned HTTP " + resp.statusCode());
            }
            decision = JSON.readTree(resp.body());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            logger.warn("rateguard: interrupted, failing open");
        } catch (Exception e) {
            logger.warn("rateguard: check failed, failing open: " + e.getMessage());
        }

        if (decision != null && "error".equals(decision.path("decision").asText())) {
            decision = null; // limiter backend unavailable: fail open
        }
        if (decision == null) {
            chain.doFilter(req, res);
            return;
        }
        JsonNode headers = decision.path("headers");
        headers.fields().forEachRemaining(h -> res.setHeader(h.getKey(), h.getValue().asText()));

        if (!decision.path("allowed").asBoolean(true)) {
            // "unauthorized" / "no_route" decisions are also allowed=false; map them.
            String d = decision.path("decision").asText("");
            int status = d.equals("unauthorized") ? 401 : d.equals("no_route") ? 404 : 429;
            res.setStatus(status);
            res.setContentType("application/json");
            res.getWriter().write("{\"error\":\"" + (status == 429 ? "rate_limited" : d) + "\"}");
            return;
        }
        chain.doFilter(req, res);
    }
}
