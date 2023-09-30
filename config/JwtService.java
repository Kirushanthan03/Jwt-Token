package com.kiru.Security.config;


import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    private static final String Secret_Key="iqduy8q94s2oB1FvFepVbu0EcKm0SLutC14wjBrExeXBEtZSmS/WZiwEn6eDn96C";

    public String extractusername(String token) {
        return extractclaims(token,Claims::getSubject);

    }

    public  <T> T extractclaims(String token, Function<Claims,T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }
    private Claims extractAllClaims(String token){
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();

    }

    private Key getSignInKey() {
        byte[] KeyBytes = Decoders.BASE64.decode(Secret_Key);
        return Keys.hmacShaKeyFor(KeyBytes);
    }

    public String generateToken (UserDetails userDetails){
        return generateToken(new HashMap<>(),userDetails);
    }
    public String generateToken(
            Map<String,Object> extraclaims,
            UserDetails userdetails
    ){
        return Jwts
                .builder()
                .setClaims(extraclaims)
                .setSubject(userdetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis()+1000*60*24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();


    }

    public boolean isTokenValid(String token,UserDetails userDetails){
        String username= extractusername(token);
        return username.equals(userDetails.getUsername())&& !isTokenExpired(token);
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date(System.currentTimeMillis()));
    }

    private Date extractExpiration(String token) {
        return extractclaims(token,Claims::getExpiration);
    }
}
