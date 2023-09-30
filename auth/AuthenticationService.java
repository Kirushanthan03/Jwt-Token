package com.kiru.Security.auth;


import com.kiru.Security.config.JwtService;
import com.kiru.Security.user.Role;
import com.kiru.Security.user.User;
import com.kiru.Security.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository repository;
    private final PasswordEncoder encoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
       var user = User.builder()
               .firstname(request.getFirstname())
               .lastname(request.getLastname())
               .email(request.getEmail())
               .password(encoder.encode(request.getPassword()))
               .role(Role.USER)
               .build();
               repository.save(user);


       var jwtToken = jwtService.generateToken(user);

               return AuthenticationResponse.builder()
                       .token(jwtToken)
                       .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {

       authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(
               request.getEmail(),
               request.getPassword()
       ));

       var user = repository.findByEmail(request.getEmail())
               .orElseThrow();

        var jwtToken = jwtService.generateToken(user);

        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
