package org.example.model;

import org.example.entities.UserInfo;

import com.fasterxml.jackson.databind.PropertyNamingStrategy;
import com.fasterxml.jackson.databind.annotation.JsonNaming;


@JsonNaming(PropertyNamingStrategy.SnakeCaseStrategy.class)

public class UserInfoDto extends UserInfo{
    
    private String userName;

    private String lastName;

    private String phoneNumber;

    private String email;
}
