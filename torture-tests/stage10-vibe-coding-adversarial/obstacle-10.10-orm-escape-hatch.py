"""Obstacle 10.10: The ORM Escape Hatch

Tests detection of SQL injection vulnerabilities when developers
"escape" from ORM safety into raw SQL.

Vibe coding often produces ORM escape hatches because:
- ORMs feel slow/limited for complex queries
- StackOverflow shows raw SQL as "the efficient way"
- Developers copy SQL snippets without using ORM properly
- Performance optimization attempts bypass ORM protections

PASS CRITERIA:
- Detect raw SQL within ORM usage
- Flag unsafe string interpolation in raw queries
- Identify mixed ORM/raw SQL patterns
- Find .extra(), .raw(), execute() misuse
"""

# =============================================================================
# DJANGO ORM ESCAPE HATCHES
# =============================================================================

from django.db import models, connection
from django.db.models import Q


class User(models.Model):
    username = models.CharField(max_length=100)
    email = models.EmailField()
    role = models.CharField(max_length=50)


def django_raw_query_vulnerable(user_input: str):
    """
    VULNERABLE: Django raw() with string formatting.

    Developer wanted a complex query, used raw() with f-string.
    """
    # WRONG: String interpolation in raw query
    return User.objects.raw(
        f"SELECT * FROM users WHERE username LIKE '%{user_input}%'"
    )


def django_extra_where_vulnerable(search_term: str):
    """
    VULNERABLE: Django extra() with user input.

    .extra() is deprecated AND dangerous with user input.
    """
    # DEPRECATED AND VULNERABLE
    return User.objects.extra(
        where=[f"username LIKE '%{search_term}%'"]
    )


def django_cursor_execute_vulnerable(table_name: str, user_id: str):
    """
    VULNERABLE: Direct cursor.execute with interpolation.

    Bypassing ORM entirely with raw cursor.
    """
    with connection.cursor() as cursor:
        # VULNERABLE: Both table_name and user_id interpolated
        cursor.execute(
            f"SELECT * FROM {table_name} WHERE id = {user_id}"
        )
        return cursor.fetchall()


def django_raw_with_params_still_wrong(column: str, value: str):
    """
    VULNERABLE: Using params for value but not column name.

    Partial parameterization - column name still injectable.
    """
    # VULNERABLE: column name is interpolated
    return User.objects.raw(
        f"SELECT * FROM users WHERE {column} = %s",
        [value]
    )


def django_filter_with_raw_annotate(user_input: str):
    """
    VULNERABLE: Raw SQL in annotate/aggregate.

    Using RawSQL annotation with user input.
    """
    from django.db.models.expressions import RawSQL

    # VULNERABLE: User input in RawSQL
    return User.objects.annotate(
        custom_field=RawSQL(
            f"SELECT data FROM extra_data WHERE user_id = %s AND type = '{user_input}'",
            [models.F('id')]
        )
    )


# =============================================================================
# SQLALCHEMY ESCAPE HATCHES
# =============================================================================

from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
from sqlalchemy import Column, Integer, String


def sqlalchemy_text_vulnerable(search: str):
    """
    VULNERABLE: SQLAlchemy text() with string formatting.

    text() is for raw SQL - formatting user input is dangerous.
    """
    engine = create_engine("sqlite:///db.sqlite")
    with Session(engine) as session:
        # VULNERABLE: f-string in text()
        result = session.execute(
            text(f"SELECT * FROM users WHERE name = '{search}'")
        )
        return result.fetchall()


def sqlalchemy_execute_string_vulnerable(user_id: str):
    """
    VULNERABLE: Plain string to execute().

    Even simpler than text() - raw string execution.
    """
    engine = create_engine("sqlite:///db.sqlite")
    with engine.connect() as conn:
        # VULNERABLE: Plain string with interpolation
        result = conn.execute(
            f"SELECT * FROM users WHERE id = {user_id}"
        )
        return result.fetchall()


def sqlalchemy_from_statement_vulnerable(order_by: str):
    """
    VULNERABLE: Raw SQL in from_statement().

    Bypassing ORM query builder with raw SQL.
    """
    session = Session(engine)
    # VULNERABLE: order_by column interpolated
    stmt = text(f"SELECT * FROM users ORDER BY {order_by}")
    return session.query(User).from_statement(stmt).all()


def sqlalchemy_filter_literal_vulnerable(role: str):
    """
    VULNERABLE: Using literal_column with user input.

    literal_column trusts its input - SQL injection possible.
    """
    from sqlalchemy import literal_column

    session = Session(engine)
    # VULNERABLE: role used in literal_column
    return session.query(User).filter(
        literal_column(f"'{role}'") == User.role
    ).all()


# =============================================================================
# PEEWEE ESCAPE HATCHES
# =============================================================================

PEEWEE_VULNERABLE_CODE = """
from peewee import *

db = SqliteDatabase('app.db')

class User(Model):
    username = CharField()
    class Meta:
        database = db


def peewee_raw_vulnerable(search):
    '''VULNERABLE: Peewee raw query with formatting.'''
    # VULNERABLE: String formatting in raw SQL
    return User.raw(f"SELECT * FROM user WHERE username LIKE '%{search}%'")


def peewee_sql_vulnerable(order_col):
    '''VULNERABLE: Peewee SQL() with user input.'''
    from peewee import SQL
    # VULNERABLE: SQL() with interpolation
    return User.select().order_by(SQL(order_col))


def peewee_execute_sql_vulnerable(table, user_id):
    '''VULNERABLE: Direct execute_sql.'''
    # VULNERABLE: Both parameters interpolated
    db.execute_sql(f"DELETE FROM {table} WHERE id = {user_id}")
"""


# =============================================================================
# TORTOISE ORM ESCAPE HATCHES
# =============================================================================

TORTOISE_VULNERABLE_CODE = """
from tortoise import Tortoise
from tortoise.models import Model
from tortoise import fields


class User(Model):
    id = fields.IntField(pk=True)
    username = fields.CharField(max_length=100)


async def tortoise_raw_vulnerable(search):
    '''VULNERABLE: Tortoise raw SQL with formatting.'''
    conn = Tortoise.get_connection("default")
    # VULNERABLE: f-string in raw query
    return await conn.execute_query(
        f"SELECT * FROM user WHERE username = '{search}'"
    )


async def tortoise_filter_raw_vulnerable(column, value):
    '''VULNERABLE: Raw SQL in filter.'''
    from tortoise.expressions import RawSQL
    # VULNERABLE: Column name interpolated
    return await User.filter(
        **{column: RawSQL(f"'{value}'")}
    )
"""


# =============================================================================
# PRISMA/TYPEORM (JS/TS) ESCAPE HATCHES
# =============================================================================

PRISMA_VULNERABLE_CODE = """
// TypeScript with Prisma

async function prismaRawVulnerable(searchTerm: string) {
    // VULNERABLE: $queryRaw with template literal
    return await prisma.$queryRaw`
        SELECT * FROM users WHERE name LIKE '%${searchTerm}%'
    `;
}

async function prismaExecuteRawVulnerable(tableName: string, userId: string) {
    // VULNERABLE: $executeRaw with interpolation
    return await prisma.$executeRaw`
        DELETE FROM ${tableName} WHERE id = ${userId}
    `;
}
"""

TYPEORM_VULNERABLE_CODE = """
// TypeScript with TypeORM

async function typeormQueryVulnerable(search: string) {
    // VULNERABLE: createQueryBuilder with raw WHERE
    return await userRepository
        .createQueryBuilder('user')
        .where(`user.name LIKE '%${search}%'`)  // VULNERABLE
        .getMany();
}

async function typeormRawVulnerable(userId: string) {
    // VULNERABLE: query() with string interpolation
    return await connection.query(
        `SELECT * FROM users WHERE id = ${userId}`
    );
}
"""


# =============================================================================
# SEQUELIZE (JS) ESCAPE HATCHES
# =============================================================================

SEQUELIZE_VULNERABLE_CODE = """
// JavaScript with Sequelize

async function sequelizeLiteralVulnerable(orderCol) {
    // VULNERABLE: Sequelize.literal with user input
    return await User.findAll({
        order: [[Sequelize.literal(orderCol), 'ASC']]  // VULNERABLE
    });
}

async function sequelizeRawVulnerable(search) {
    // VULNERABLE: sequelize.query with interpolation
    return await sequelize.query(
        `SELECT * FROM users WHERE name = '${search}'`,
        { type: QueryTypes.SELECT }
    );
}

async function sequelizeWhereRawVulnerable(column, value) {
    // VULNERABLE: where with Sequelize.where and literal
    return await User.findAll({
        where: Sequelize.where(
            Sequelize.col(column),  // Column from user - VULNERABLE
            value
        )
    });
}
"""


# =============================================================================
# EXPECTED DETECTIONS
# =============================================================================

ORM_ESCAPE_VULNERABILITIES = {
    "django": [
        "django_raw_query_vulnerable",
        "django_extra_where_vulnerable",
        "django_cursor_execute_vulnerable",
        "django_raw_with_params_still_wrong",
        "django_filter_with_raw_annotate",
    ],
    "sqlalchemy": [
        "sqlalchemy_text_vulnerable",
        "sqlalchemy_execute_string_vulnerable",
        "sqlalchemy_from_statement_vulnerable",
        "sqlalchemy_filter_literal_vulnerable",
    ],
    "patterns_to_detect": [
        "raw() with f-string/format",
        ".extra() usage (deprecated)",
        "cursor.execute() with interpolation",
        "text() with interpolation",
        "literal_column() with user input",
        "RawSQL with interpolation",
        "$queryRaw with interpolation",
        "Sequelize.literal with user input",
    ],
}


# =============================================================================
# HELPER STUBS
# =============================================================================

engine = None
