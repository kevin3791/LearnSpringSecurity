package com.kevinmcg.learnspringsecurity.model;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class MyUserDetailsService implements UserDetailsService {
	
	@Autowired
	private MyUserRepository repository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		// TODO Auto-generated method stub
		Optional<MyUser> user =  repository.findByUsername(username);
		if (user.isPresent()) {
			var userObj = user.get();
			UserDetails adminUser = User.builder()
					.username(userObj.getUsername())
					.password(userObj.getPassword())
					.roles(getRoles(userObj))
					.build();
			
			return adminUser;
		} else {
			throw new UsernameNotFoundException(username);
		}
	}

	private String[] getRoles(MyUser user) {
		if (user.getRole() == null) {
			return new String[]{"USER"};
		}
		
		return user.getRole().split(",");
	}
}
