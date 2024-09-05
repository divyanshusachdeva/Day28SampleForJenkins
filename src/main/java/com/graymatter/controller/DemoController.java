package com.graymatter.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DemoController {

	@GetMapping("/demo")
	public String sayHello() {
		return "Hello!";
	}
	
	@GetMapping("/name/{name}")
	public String printName(@PathVariable ("name") String name) {
		return name;
	}
	
}
