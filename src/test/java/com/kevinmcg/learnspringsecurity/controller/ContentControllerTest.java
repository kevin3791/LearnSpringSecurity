package com.kevinmcg.learnspringsecurity.controller;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpStatus;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;

@SpringBootTest
@AutoConfigureMockMvc
public class ContentControllerTest {

	@Autowired
	private MockMvc mockMvc;
	
	@Test
	public void testHomeAccessible_WithoutLogin() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/home"))
			.andExpect(MockMvcResultMatchers.status().is(HttpStatus.OK.value()));
	}
	
	@Test
	public void testUserHomeAccessible_WithoutLogin() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/user/home"))
			.andExpect(MockMvcResultMatchers.status().is(HttpStatus.FOUND.value()));
	}
	
	@Test
	@WithMockUser(username="tester", roles="USER")
	public void testUserHomeAccessible_WithLogin() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/user/home"))
			.andExpect(MockMvcResultMatchers.status().is(HttpStatus.OK.value()));
	}
	
	@Test
	public void testAdminHomeNotAccessible_WithoutLogin() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/admin/home"))
			.andExpect(MockMvcResultMatchers.status().is(HttpStatus.FOUND.value()));
	}
	
	@Test
	@WithMockUser(username="tester", roles="ADMIN")
	public void testUserHomeAccessible_WithAdminLogin() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/admin/home"))
			.andExpect(MockMvcResultMatchers.status().is(HttpStatus.OK.value()));
	}
	
	@Test
	@WithMockUser(username="tester", roles="USER")
	public void testAdminHomeNotAccessible_WithUserLogin() throws Exception {
		mockMvc.perform(MockMvcRequestBuilders.get("/admin/home"))
			.andExpect(MockMvcResultMatchers.status().is(HttpStatus.FORBIDDEN.value()));
	}
}
