package net.codejava;

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

public class PasswordGenerator {

	public static void main(String[] args) {
		BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
		String rawPassword = "tommy";
		String encodedPassword = encoder.encode(rawPassword);

		System.out.println(encodedPassword);
		Argon2PasswordEncoder encoderArgon2 = new Argon2PasswordEncoder(16, 32, 1, 1 << 14, 2);

		String encodedPasswordArgon2 = encoderArgon2.encode(rawPassword);
		System.out.println(encodedPasswordArgon2);
	}

}
