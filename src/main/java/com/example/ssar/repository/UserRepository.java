package com.example.ssar.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.ssar.entity.UserEntity;

public interface UserRepository extends JpaRepository<UserEntity, Integer> {

	boolean existsByUsername(String username);

	UserEntity findByUsername(String username);

}
