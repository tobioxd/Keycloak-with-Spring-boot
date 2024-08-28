package com.tobioxd.keycloak.payload.dto;

import lombok.*;

@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor

public class UserDTO {

    private String username;

    private String password;
    
    private String email;

    private String firstName;

    private String lastName;

}
