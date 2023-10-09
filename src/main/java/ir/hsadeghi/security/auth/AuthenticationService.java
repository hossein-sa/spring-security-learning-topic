package ir.hsadeghi.security.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import ir.hsadeghi.security.config.JwtService;
import ir.hsadeghi.security.token.Token;
import ir.hsadeghi.security.token.TokenRepository;
import ir.hsadeghi.security.token.TokenType;
import ir.hsadeghi.security.user.Role;
import ir.hsadeghi.security.user.User;
import ir.hsadeghi.security.user.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Service;

import java.io.IOException;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository repository;
    private final TokenRepository tokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    // Register a new user
    public AuthenticationResponse register(RegisterRequest request) {
        // Create a new User object with the information from the RegisterRequest
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword())) // Encrypt the password
                .role(request.getRole())
                .build();

        // Save the user to the repository
        var savedUser = repository.save(user);

        // Generate JWT token and refresh token
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);

        // Save the user's JWT token
        saveUserToken(savedUser, jwtToken);

        // Build and return an AuthenticationResponse
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    // Authenticate a user and generate a JWT token
    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        // Use Spring Security's authentication manager to verify the credentials
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        // Find the user by email
        var user = repository.findByEmail(request.getEmail())
                .orElseThrow(); // Handle if the user is not found

        // Generate a new JWT token and refresh token
        var jwtToken = jwtService.generateToken(user);
        var refreshToken = jwtService.generateRefreshToken(user);

        // Revoke all existing tokens for this user
        revokeAllUserTokens(user);

        // Save the new JWT token
        saveUserToken(user, jwtToken);

        // Build and return an AuthenticationResponse
        return AuthenticationResponse.builder()
                .accessToken(jwtToken)
                .refreshToken(refreshToken)
                .build();
    }

    // Revoke all tokens for a user
    private void revokeAllUserTokens(User user) {
        // Find all valid user tokens and mark them as expired and revoked
        var validUserTokens = tokenRepository.findAllValidTokensByUser(user.getId());
        if (validUserTokens.isEmpty()) {
            return;
        }
        validUserTokens.forEach(token -> {
            token.setExpired(true);
            token.setRevoked(true);
        });
        tokenRepository.saveAll(validUserTokens);
    }

    // Save a new user token
    private void saveUserToken(User user, String jwtToken) {
        // Create a new Token object and save it to the repository
        var token = Token.builder()
                .user(user)
                .token(jwtToken)
                .tokenType(TokenType.BEARER)
                .expired(false)
                .revoked(false)
                .build();
        tokenRepository.save(token);
    }

    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        final String refreshToken;
        final String userEmail;

        // Check if the Authorization header is present and starts with "Bearer "
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return;
        }
        refreshToken = authHeader.substring(7);

        // Extract the user's email from the refresh token
        userEmail = jwtService.extractUsername(refreshToken);

        if (userEmail != null) {
            // Find the user by email
            var user = this.repository.findByEmail(userEmail)
                    .orElseThrow();

            // Check if the refresh token is valid
            if (jwtService.isTokenValid(refreshToken, user)) {
                // Generate a new access token
                var accessToken = jwtService.generateToken(user);

                // Revoke all existing tokens for this user
                revokeAllUserTokens(user);

                // Save the new access token
                saveUserToken(user, accessToken);

                // Build and write an AuthenticationResponse to the response's output stream
                var authResponse = AuthenticationResponse.builder()
                        .accessToken(accessToken)
                        .refreshToken(refreshToken)
                        .build();
                new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
            }
        }
    }
}
