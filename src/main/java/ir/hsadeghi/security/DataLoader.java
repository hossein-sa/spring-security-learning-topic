package ir.hsadeghi.security;

import ir.hsadeghi.security.auth.AuthenticationService;
import ir.hsadeghi.security.auth.RegisterRequest;
import ir.hsadeghi.security.user.Role;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.stereotype.Component;

import static ir.hsadeghi.security.user.Role.ADMIN;
import static ir.hsadeghi.security.user.Role.MANAGER;

@Component
@RequiredArgsConstructor
public class DataLoader implements CommandLineRunner {
    private final AuthenticationService authenticationService;

    @Override
    public void run(String... args) throws Exception {
        var admin = createAndRegisterUser("Admin", "Admin", "admin@mail.com", "password", ADMIN);
        System.out.println("Admin token: " + authenticationService.register(admin).getAccessToken());


        var manager = createAndRegisterUser("Manager", "Manager", "manager@mail.com", "password", MANAGER);
        System.out.println("Manager token: " + authenticationService.register(manager).getAccessToken());
    }

    private RegisterRequest createAndRegisterUser(String firstname, String lastname, String email, String password, Role role) {
        return RegisterRequest.builder()
                .firstname(firstname)
                .lastname(lastname)
                .email(email)
                .password(password)
                .role(role)
                .build();
    }
}
