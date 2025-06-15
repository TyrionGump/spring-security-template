create table mock_user
(
    id       int generated always as identity primary key,
    username text not null unique,
    password text not null,
    email    text not null,
    role     text not null
);

insert into mock_user
values (default, 'admin', '{noop}12345', 'admin@email.com', 'admin');

-- password 12345 is hashed via Bcrypt
insert into mock_user
values (default, 'user', '{bcrypt}$2a$10$VVlYlP4xwSivh0KDMM7qqO5e4iPf4efMxaZJhd2.WAt1PMzrV/aim',
        'user@email.com', 'user');