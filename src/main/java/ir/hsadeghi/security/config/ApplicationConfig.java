package ir.hsadeghi.security.config;

import ir.hsadeghi.security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {
    private final UserRepository repository;

    // Define a bean for the UserDetailsService
    @Bean
    public UserDetailsService userDetailsService(){
        // This method returns a UserDetailsService that looks up user details by their email in the UserRepository.
        // It throws a UsernameNotFoundException if the user is not found.
        return username -> repository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
    }

    // Define a bean for the AuthenticationProvider
    @Bean
    public AuthenticationProvider authenticationProvider(){
        // Create a DaoAuthenticationProvider, which is an AuthenticationProvider implementation
        // It uses the userDetailsService() to load user details and the passwordEncoder() to encode and check passwords.
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService());
        authProvider.setPasswordEncoder(passwordEncoder());
        return authProvider;
    }

    // Define a bean for the AuthenticationManager
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        // This method returns the AuthenticationManager from the provided AuthenticationConfiguration.
        return config.getAuthenticationManager();
    }

    // Define a bean for the PasswordEncoder
    @Bean
    public PasswordEncoder passwordEncoder() {
        // This method returns a BCryptPasswordEncoder, which is used to securely hash and verify passwords.
        return new BCryptPasswordEncoder();
    }
}
