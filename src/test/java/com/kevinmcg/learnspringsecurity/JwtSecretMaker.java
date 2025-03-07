package com.kevinmcg.learnspringsecurity;

import javax.crypto.SecretKey;

import org.junit.jupiter.api.Test;

import io.jsonwebtoken.Jwts;
import jakarta.xml.bind.DatatypeConverter;

public class JwtSecretMaker {

	@Test
	public void generateSecretKey() {
		SecretKey secretKey = Jwts.SIG.HS512.key().build();
		String encodedKey = DatatypeConverter.printHexBinary(secretKey.getEncoded());
		System.out.println("Secret Key = " + encodedKey);
	}
}
