package org.example.request;

import lombok.*;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class RefreshTokenRequestDto {
    private String token;
}
