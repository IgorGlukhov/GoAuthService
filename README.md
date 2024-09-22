Прописать свой IP в переменную localIP
Смонтировать и запустить Docker контейнер БД https://github.com/users/IgorGlukhov/packages/container/package/psqlauthservice (порты 5432:5432)

1 REST маршрут(выдает пару Access, Refresh токенов для пользователя с идентификатором (GUID) указанным в параметре запроса)
Запрос GET
Пример запроса:
http://192.168.0.103:8000/access?user_id=b5891a16-806b-47a0-8c02-17ef3c3be819

Пример ответа:
{
    "access_token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiYjU4OTFhMTYtODA2Yi00N2EwLThjMDItMTdlZjNjM2JlODE5IiwiaXAiOiIxNzIuMTcuMC4xOjM5OTMyIiwidG9rZW5faWQiOiI0MDkxOTNmOS00M2I1LTQ2ZWQtODU0Ni0xMjE3ZDhhMmIyYmMiLCJleHAiOjE3MjY5NTA3NTF9.48G9_HqZJ3s8jJ6kDu6iorjA49KTfVSp1NR-MnA03YobzTUIlPsFGcosjeswUlUW5wL1KSfwB_0sRs7oe_QMdg",
    "refresh_token": "YjU4OTFhMTYtODA2Yi00N2EwLThjMDItMTdlZjNjM2JlODE5MTcyLjE3LjAuMTozOTkzMjIwMjQtMDktMjEgMjA6MTc6MzEuMTAwOTg4NTcxICswMDAwIFVUQyBtPSs3LjgxMzQyODQ4OQ=="
}

2 REST маршрут(выполняет Refresh операцию на пару Access, Refresh токенов)
Запрос POST
Пример запроса:
http://192.168.0.103:8000/refresh
Тело запроса:
{
    "access_token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiYjU4OTFhMTYtODA2Yi00N2EwLThjMDItMTdlZjNjM2JlODE5IiwiaXAiOiIxNzIuMTcuMC4xOjM5OTMyIiwidG9rZW5faWQiOiI0MDkxOTNmOS00M2I1LTQ2ZWQtODU0Ni0xMjE3ZDhhMmIyYmMiLCJleHAiOjE3MjY5NTA3NTF9.48G9_HqZJ3s8jJ6kDu6iorjA49KTfVSp1NR-MnA03YobzTUIlPsFGcosjeswUlUW5wL1KSfwB_0sRs7oe_QMdg",
    "refresh_token": "YjU4OTFhMTYtODA2Yi00N2EwLThjMDItMTdlZjNjM2JlODE5MTcyLjE3LjAuMTozOTkzMjIwMjQtMDktMjEgMjA6MTc6MzEuMTAwOTg4NTcxICswMDAwIFVUQyBtPSs3LjgxMzQyODQ4OQ=="
}

Пример ответа:
{
    "access_token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoiYjU4OTFhMTYtODA2Yi00N2EwLThjMDItMTdlZjNjM2JlODE5IiwiaXAiOiIxNzIuMTcuMC4xOjM5OTMyIiwidG9rZW5faWQiOiI2NmE2NGY4MS1kZDgxLTQ2NjAtYWM4MS0yMGY4N2JhMjRhOTciLCJleHAiOjE3MjY5NTA3NTh9.z0e3kn1068gRDSy_ojQdExHVMxqI1PRQaG0XJNMdizQUcNB9m8EJOyoLJiXeQhPFxUNxNUEShfGVvG9xs-I4Pg",
    "refresh_token": "YjU4OTFhMTYtODA2Yi00N2EwLThjMDItMTdlZjNjM2JlODE5MTcyLjE3LjAuMTozOTkzMjIwMjQtMDktMjEgMjA6MTc6MzguMzE4MTExMzg4ICswMDAwIFVUQyBtPSsxNS4wMzE0MDU5Nzk="
}
