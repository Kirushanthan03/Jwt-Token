package com.kiru.Security.auth;


import lombok.*;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AuthenticationRequest {


    private String email;

    @NonNull
    private String password;
}
