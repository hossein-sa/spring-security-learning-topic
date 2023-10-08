package ir.hsadeghi.security.user;

import ir.hsadeghi.security.token.Token;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor

@Entity
@Table(name = "_user") // Specifies the name of the database table

public class User implements UserDetails {
    @Id // Marks the id field as the primary key
    @GeneratedValue(strategy = GenerationType.IDENTITY) // Specifies the generation strategy for the primary key
    private Integer id; // Unique identifier for the user

    private String firstname; // User's first name
    private String lastname; // User's last name
    private String email; // User's email address
    private String password; // User's password

    @Enumerated(EnumType.STRING)
    private Role role; // User's role (you should have an enum called 'Role' defined)
    @OneToMany(mappedBy = "user")
    private List<Token> tokens;

    // Override methods from UserDetails interface for Spring Security

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Convert the user's role to a SimpleGrantedAuthority for Spring Security
        return role.getAuthorities();
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true; // Account expiration logic can be added here
    }

    @Override
    public boolean isAccountNonLocked() {
        return true; // Account locking logic can be added here
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true; // Credentials expiration logic can be added here
    }

    @Override
    public boolean isEnabled() {
        return true; // Account enable/disable logic can be added here
    }

    // Getters and setters are generated by Lombok's @Data annotation
}
