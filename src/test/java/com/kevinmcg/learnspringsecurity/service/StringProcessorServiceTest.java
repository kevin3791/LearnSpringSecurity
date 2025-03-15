package com.kevinmcg.learnspringsecurity.service;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class StringProcessorServiceTest {

	@Autowired
	StringProcessorService stringProcessorService;
	
	@Test
	public void testIsPalindrome_ValidPalindrome() {
		var result = stringProcessorService.isPalindrome("kayak");
		
		Assertions.assertTrue(result);
	}
	
	@Test
	public void testIsPalindrome_InvalidPalindrome() {
		var result = stringProcessorService.isPalindrome("kayak123");
		
		Assertions.assertFalse(result);
	}
	
	@Test
	public void testIsPalindrome_NullInput() {
		Assertions.assertThrows(NullPointerException.class, () -> {
			stringProcessorService.isPalindrome(null);
		});
	}
}
