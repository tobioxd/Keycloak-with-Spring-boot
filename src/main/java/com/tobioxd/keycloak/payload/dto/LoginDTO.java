package com.tobioxd.keycloak.payload.dto;

import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor

public class LoginDTO {

    private String username;

    private String password;

}
