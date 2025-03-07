package com.kevinmcg.learnspringsecurity.webtoken;

import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import javax.crypto.SecretKey;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {
	private static final String SECRET_KEY = "D92893F719B4CBD8E9F6B9287B617C689CFA0248990C0309532678436932036121399E0F675E1246AF4AC37CDE68503FE6B70B6EC61DB94127D2B5A2C62E4799";
	private static final long VALIDITY = TimeUnit.MINUTES.toMillis(30);
	
	public String generateToken(UserDetails userDetails) {
		Map<String, String> claims = new HashMap<String, String>();
		claims.put("iss","https://secure.genuinecoder.com");
		claims.put("name", "Kevin McGonagle");
		
		return
			Jwts.builder()
				.claims(claims)
				.subject(userDetails.getUsername())
				.issuedAt(Date.from(Instant.now()))
				.expiration(Date.from(Instant.now().plusMillis(VALIDITY)))
				.signWith(generateKey())
				.compact();
	}
	
	public String extractUsername(String jwt) {
		Claims claims = getClaims(jwt);
		return claims.getSubject();
	}

	private Claims getClaims(String jwt) {
		Claims claims = Jwts.parser()
			.verifyWith(generateKey())
			.build()
			.parseSignedClaims(jwt)
			.getPayload();
		return claims;
	}
	
	private SecretKey generateKey() {
		byte[] decodedKey = Base64.getDecoder().decode(SECRET_KEY);
		
		return Keys.hmacShaKeyFor(decodedKey);
	}

	public boolean isTokenValid(String jwt) {
		Claims claims = getClaims(jwt);
		Date expirationDate = claims.getExpiration();
		
		return expirationDate.after(Date.from(Instant.now()));
	}
}
