package ir.hsadeghi.security.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService service;

    // This is a constructor injection of the AuthenticationService.
    // Spring will automatically inject the service when creating an instance of this controller.
    // @RequiredArgsConstructor is a Lombok annotation that generates a constructor with required fields.

    // This annotation defines that this class is a RESTful controller.
    // It maps to the "/api/v1/auth" base URL.
    // All the methods in this class will handle requests under this base URL.

    @PostMapping("/register")
    public ResponseEntity<AuthenticationResponse> register(
            @RequestBody RegisterRequest request
    ) {
        // This method handles HTTP POST requests to "/api/v1/auth/register".
        // It expects a JSON request body, which is automatically deserialized to a RegisterRequest object.

        // It returns a ResponseEntity containing an AuthenticationResponse.
        // ResponseEntity is used to wrap the response, allowing you to set HTTP status codes and response bodies.

        // It calls the "register" method of the "service" object to perform the registration logic.

        return ResponseEntity.ok(service.register(request));
    }

    @PostMapping("/authenticate")
    public ResponseEntity<AuthenticationResponse> authenticate(
            @RequestBody AuthenticationRequest request
    ) {
        // This method handles HTTP POST requests to "/api/v1/auth/authenticate".
        // It's similar to the "register" method but handles authentication requests.
        return ResponseEntity.ok(service.authenticate(request));
    }

    @PostMapping("/refresh_token")
    public void refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) throws IOException {
        // This method handles HTTP POST requests to "/api/v1/auth/refresh_token".
        // It doesn't return a ResponseEntity but instead directly interacts with the response.

        // It calls the "refreshToken" method of the "service" object to refresh the authentication token.
        // This method can throw an IOException, so it's declared in the method signature.

        service.refreshToken(request, response);
    }
}
