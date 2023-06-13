package ru.kata.spring.boot_security.demo.services;

import org.springframework.security.core.userdetails.UserDetailsService;
import ru.kata.spring.boot_security.demo.entities.Role;
import ru.kata.spring.boot_security.demo.entities.User;

import java.util.List;

public interface UserService extends UserDetailsService {
    boolean createUser(User user);

    List<User> readAllUsers();

    User findUserByUsername(String username);

    void update(User user);

    User getUserById(Long id);

    void deleteUserById(Long id);

}
