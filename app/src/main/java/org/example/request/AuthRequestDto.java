package org.example.request;

import lombok.*;

@Data
@AllArgsConstructor 
@NoArgsConstructor
@Builder
public class AuthRequestDto {
    private String username;
    private String password;
}
