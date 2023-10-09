package ir.hsadeghi.security.config;

import ir.hsadeghi.security.token.TokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {
    private final TokenRepository tokenRepository;

    // This LogoutService class implements the LogoutHandler interface, which is invoked when a user logs out of your application.

    @Override
    public void logout(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) {
        final String authHeader = request.getHeader("Authorization");
        final String jwt;

        // Check if the Authorization header is present and starts with "Bearer "
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }
        jwt = authHeader.substring(7);

        // Find the stored token in the TokenRepository based on the JWT token
        var storedToken = tokenRepository.findByToken(jwt)
                .orElse(null);

        if (storedToken != null) {
            // Mark the stored token as expired and revoked
            storedToken.setExpired(true);
            storedToken.setRevoked(true);

            // Save the updated token in the repository
            tokenRepository.save(storedToken);
        }
    }
}
