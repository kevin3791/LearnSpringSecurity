package com.kevinmcg.learnspringsecurity.controller;

import org.hamcrest.Matchers;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.kevinmcg.learnspringsecurity.model.MyUser;

@SpringBootTest
@AutoConfigureMockMvc
public class RegistrationControllerTest {

	@Autowired
	private MockMvc mockMvc;
	
	@Autowired
	ObjectMapper objectMapper;
		
	@Test
	public void testCreateUser_ValidUser() throws JsonProcessingException, Exception {
		var user = new MyUser();
		user.setUsername("Claire");
		user.setPassword("password");
		user.setRole("USER");
		
		mockMvc.perform(
			MockMvcRequestBuilders.post("/register/user")
				.contentType(MediaType.APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(user))
		)
		.andExpect(MockMvcResultMatchers.status().isOk())
		.andExpect(MockMvcResultMatchers.jsonPath("$.username").value("Claire"))
		.andExpect(MockMvcResultMatchers.jsonPath("$.password").value(Matchers.not(1234)))
		.andExpect(MockMvcResultMatchers.jsonPath("$.id").exists())
		.andExpect(MockMvcResultMatchers.jsonPath("$.role").exists());
	}
	
	@Test
	public void testCreateUser_WithoutPassword() throws JsonProcessingException, Exception {
		var user = new MyUser();
		user.setUsername("Claire");
		
		mockMvc.perform(
			MockMvcRequestBuilders.post("/register/user")
				.contentType(MediaType.APPLICATION_JSON)
				.content(objectMapper.writeValueAsString(user))
		)
		.andExpect(MockMvcResultMatchers.status().isInternalServerError());
	}
}
