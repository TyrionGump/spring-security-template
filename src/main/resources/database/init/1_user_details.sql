create table mock_user
(
    id       int generated always as identity primary key,
    username text not null unique,
    password text not null,
    email    text not null,
    role     text not null
);

-- Spring Security expects roles to be represented as GrantedAuthority strings prefixed with "ROLE_".
-- By storing "ROLE_ADMIN" and "ROLE_USER" here, you align your data directly
-- with Spring Security’s conventions (so you can call hasRole("ADMIN") / hasRole("USER") in your config).
-- See org.bugmakers404.spring.security.template.config.SecurityFilterConfig.
insert into mock_user
values (default, 'admin', '{noop}12345', 'admin@email.com', 'ROLE_ADMIN');

-- password 12345 is hashed via Bcrypt
insert into mock_user
values (default, 'user', '{bcrypt}$2a$10$VVlYlP4xwSivh0KDMM7qqO5e4iPf4efMxaZJhd2.WAt1PMzrV/aim',
        'user@email.com', 'ROLE_USER');
