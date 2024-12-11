Подробное описание:

    Импорт необходимых библиотек:
        FastAPI из fastapi для создания веб-приложения.
        BaseModel из pydantic для валидации данных.
        create_engine, Column, Integer, String, declarative_base, sessionmaker, Session из sqlalchemy для работы с базой данных.
        HTTPException, Depends из fastapi для обработки исключений и зависимостей.
        IntegrityError из sqlalchemy.exc для обработки ошибок уникальности.

    Настройка базы данных:
        Создается подключение к MySQL базе данных с использованием SQLAlchemy.
        Определяется сессия для взаимодействия с базой данных.
        Создается базовый класс для моделей.

    Определение модели пользователя:
        SQLAlchemy модель User с полями id, name, email.
        Pydantic модели UserCreate для валидации данных при создании пользователя и UserResponse для возврата данных пользователя.

    Создание маршрутов:
        Маршрут GET /users/{user_id} для получения пользователя по ID. Если пользователь не найден, возвращается ошибка 404.
        Маршрут POST /users/ для создания нового пользователя. Если электронная почта уже зарегистрирована, возвращается ошибка 400.

Этот пример предоставляет базовый функционал и может быть расширен в зависимости от требований вашего проекта. Не забудьте заменить

```py
SQLALCHEMY_DATABASE_URL = "mysql+pymysql://isp_is_test:12345@192.168.25.23/isp_is_test"
# user:password@url/таблица_БД - на реальные учетные данные и имя базы данных MySQL.
```

Запуск
pip install "fastapi[standard]"

- `pip install -r requirements.txt`
- `fastapi dev main.py` или `python -m fastapi dev main.py  `
