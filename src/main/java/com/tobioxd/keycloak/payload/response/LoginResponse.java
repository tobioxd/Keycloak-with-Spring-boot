package com.tobioxd.keycloak.payload.response;

import lombok.*;

@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
@Builder

public class LoginResponse {

    private String access_token;

    private String token_type;

    private String refresh_token;

    private String expires_in;

    private String refresh_expires_in;

}
