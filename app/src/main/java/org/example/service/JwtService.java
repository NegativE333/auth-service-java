package org.example.service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

  public static final String SECRET_KEY =
    "9mXG6q3rT9VqOJtQuYwxZpD5aGsmJ0bJHhP/8mVvylo=";

  public String extractUsername(String token) {
    return extactClaim(token, Claims::getSubject);
  }

  public <T> T extactClaim(String token, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

  public Date extractExpiration(String token) {
    return extactClaim(token, Claims::getExpiration);
  }

  private Boolean isTokenExpired(String token) {
    return extractExpiration(token).before(new Date());
  }

  public Boolean validateToken(String token, UserDetails userdetails) {
    final String username = extractUsername(token);
    return (
      (username.equals(userdetails.getUsername())) && !isTokenExpired(token)
    );
  }

  public String GenerateToken(String username){
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, username);
    }

  public String createToken(Map<String, Object> claims, String username){
    return Jwts
      .builder()
      .setClaims(claims)
      .setSubject(username)
      .setIssuedAt(new Date(System.currentTimeMillis()))
      .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 1))
      .signWith(getSignKey(), SignatureAlgorithm.HS256)
      .compact();
  }

  private Claims extractAllClaims(String token) {
    return Jwts
      .parser()
      .setSigningKey(getSignKey())
      .build()
      .parseClaimsJws(token)
      .getBody();
  }

  private Key getSignKey() {
    byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
    return Keys.hmacShaKeyFor(keyBytes);
  }
}
