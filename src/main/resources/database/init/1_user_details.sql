create table mock_user
(
    id       int generated always as identity primary key,
    username text not null unique,
    password text not null,
    email    text not null,
    role     text not null
);

insert into mock_user
values (default, 'admin', 12345, 'admin@email.com', 'admin');

insert into mock_user
values (default, 'user', 12345, 'user@email.com', 'admin');