package com.kevinmcg.learnspringsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.kevinmcg.learnspringsecurity.model.MyUserDetailsService;
import com.kevinmcg.learnspringsecurity.webtoken.JwtService;
import com.kevinmcg.learnspringsecurity.webtoken.LoginForm;

@RestController
public class ContentController {
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private JwtService jwtService;
	
	@Autowired
	private MyUserDetailsService myUserDetailsService;

	@GetMapping("/home")
	public String handleHome() {
		return "Welcome to Home!";
	}
	
	@GetMapping("/admin/home")
	public String handleAdminHome() {
		return "Welcome to Admin Home!";
	}
	
	@GetMapping("/user/home")
	public String handleUserHome() {
		return "Welcome to User Home!";
	}

//	@GetMapping("/login")
//	public String handleLogin() {
//		return "custom_login";
//	}
	
	@PostMapping("/authenticate")
	public String authenticateAndGetToken(@RequestBody LoginForm loginForm) {
		// Check if username and password are correct
		Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(loginForm.getUsername(), loginForm.getPassword()));
		if (authentication.isAuthenticated()) {
			// If authenticated, generate and return a JWT token
			return jwtService.generateToken(myUserDetailsService.loadUserByUsername(loginForm.getUsername()));
		} else {
			throw new UsernameNotFoundException("Invalid credentials");
		}
	}
}
