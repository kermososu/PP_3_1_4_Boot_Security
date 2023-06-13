package ru.kata.spring.boot_security.demo.controllers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.*;
import ru.kata.spring.boot_security.demo.entities.Role;
import ru.kata.spring.boot_security.demo.entities.User;
import ru.kata.spring.boot_security.demo.repositories.RoleRepository;
import ru.kata.spring.boot_security.demo.services.UserService;

import javax.validation.Valid;
import java.security.Principal;
import java.util.List;


@Controller
public class UserController {

    private final UserService userService;
    private final RoleRepository roleRepository;

    @Autowired
    public UserController(UserService userService, RoleRepository roleRepository) {
        this.userService = userService;
        this.roleRepository = roleRepository;
    }

    @GetMapping("/")
    public String index(@AuthenticationPrincipal User user, ModelMap model) {
        model.addAttribute("users", userService.readAllUsers());
        model.addAttribute("user", user);
        model.addAttribute("roles", roleRepository.findAll());
        return "index";
    }

    @GetMapping("/registration")
    public String newUser(@ModelAttribute("user") User user, ModelMap model) {

        List<Role> roles = roleRepository.findAll();
        model.addAttribute("allRoles", roles);
        return "registration";
    }

    @PostMapping()
    public String registration(@ModelAttribute("user") @Valid User user) {
        if (!userService.createUser(user)) {
            return "registration";
        }
        userService.createUser(user);
        return "redirect:/login";
    }

    @GetMapping("/user")
    public String user(ModelMap model, Principal principal) {
        model.addAttribute("user", userService.findUserByUsername(principal.getName()));
        return "user";
    }
}
