package com.ronald.springSecurityJWT;

import com.ronald.springSecurityJWT.entities.PermissionEntity;
import com.ronald.springSecurityJWT.entities.RoleEntity;
import com.ronald.springSecurityJWT.entities.RoleEnum;
import com.ronald.springSecurityJWT.entities.UserEntity;
import com.ronald.springSecurityJWT.repositories.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

import java.util.List;
import java.util.Set;

@SpringBootApplication
public class SpringSecurityJwtApplication {

	public static void main(String[] args) {
		SpringApplication.run(SpringSecurityJwtApplication.class, args);
	}

	@Bean
	CommandLineRunner init(UserRepository userRepository){
		return args -> {
			//Creacion de permisos
			PermissionEntity createPermission = PermissionEntity.builder()
					.name("CREATE")
					.build();

			PermissionEntity readPermission = PermissionEntity.builder()
					.name("READ")
					.build();

			PermissionEntity updatePermission = PermissionEntity.builder()
					.name("UPDATE")
					.build();

			PermissionEntity deletePermission = PermissionEntity.builder()
					.name("DELETED")
					.build();

			PermissionEntity refactorPermission = PermissionEntity.builder()
					.name("REFACTOR")
					.build();

			//Creacion de roles

			RoleEntity roleAdmin = RoleEntity.builder()
					.roleEnum(RoleEnum.ADMIN)
					.permissionList(Set.of(createPermission, readPermission, updatePermission, deletePermission))
					.build();

			RoleEntity roleUser = RoleEntity.builder()
					.roleEnum(RoleEnum.USER)
					.permissionList(Set.of(createPermission, readPermission))
					.build();

			RoleEntity roleInvited = RoleEntity.builder()
					.roleEnum(RoleEnum.INVITED)
					.permissionList(Set.of(readPermission))
					.build();

			//creacion de usuarios
			UserEntity userRonald = UserEntity.builder()
					.username("ronald")
					.password("$2a$10$qXbvbwRHFEkIl.OcuEIO.egiLXjgtUKbVzGE248.aoArOCkMevzVy")
					.isEnabled(true)
					.accountNoExpired(true)
					.accountNoLocked(true)
					.credentialsNoExpired(true)
					.roles(Set.of(roleAdmin))
					.build();

			UserEntity userDiego = UserEntity.builder()
					.username("diego")
					.password("$2a$10$qXbvbwRHFEkIl.OcuEIO.egiLXjgtUKbVzGE248.aoArOCkMevzVy")
					.isEnabled(true)
					.accountNoExpired(true)
					.accountNoLocked(true)
					.credentialsNoExpired(true)
					.roles(Set.of(roleUser))
					.build();

			UserEntity userNicolas = UserEntity.builder()
					.username("nicolas")
					.password("$2a$10$qXbvbwRHFEkIl.OcuEIO.egiLXjgtUKbVzGE248.aoArOCkMevzVy")
					.isEnabled(true)
					.accountNoExpired(true)
					.accountNoLocked(true)
					.credentialsNoExpired(true)
					.roles(Set.of(roleInvited))
					.build();

			userRepository.saveAll(List.of(userRonald, userDiego, userNicolas));
		};
	}
}
