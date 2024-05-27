package com.example.ssar.dto;

import java.util.ArrayList;
import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.example.ssar.entity.UserEntity;

public class CustomUserDetails implements UserDetails {

    private static final long serialVersionUID = 7089655268258705867L;
	private final UserEntity userEntity;

    public CustomUserDetails(UserEntity userEntity) {
    	
        this.userEntity = userEntity;
        
    }


    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        Collection<GrantedAuthority> collection = new ArrayList<>();

        collection.add(new GrantedAuthority() {

            private static final long serialVersionUID = -4978707136914028338L;

			@Override
            public String getAuthority() {

                return userEntity.getRole();
            }
        });

        return collection;
    }


	@Override
	public String getPassword() {
		 return userEntity.getPassword();
	}


	@Override
	public String getUsername() {
		 return userEntity.getUsername();
	}
}
