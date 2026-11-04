<?php
// Database queries for Symfony (sdk/protocols/queries.md): a Doctrine DBAL
// middleware, DBAL's own public way in (3.2 and later, and 4), so every query
// Doctrine runs, the ORM's included, is timed for Health → Server speed →
// Queries. DoctrineBundle puts it on every connection when it carries the
// doctrine.middleware tag (README: "Symfony"):
//
//   AnalyticsPlatform\Symfony\QueryMiddleware:
//       tags: [doctrine.middleware]
//
// Timed where the database is asked: a connection's exec() and query(), and
// a prepared statement's execute(), under its SQL (bound values are never
// read). A TimedPdo under Doctrine leaves the query to this (Queries::timed()).
// The three wrappers below are declared with it, in this file, since only it
// makes them.

namespace AnalyticsPlatform\Symfony;

use AnalyticsPlatform\Platform;
use AnalyticsPlatform\Queries;
use Doctrine\DBAL\Driver;
use Doctrine\DBAL\Driver\Connection as DriverConnection;
use Doctrine\DBAL\Driver\Middleware;
use Doctrine\DBAL\Driver\Middleware\AbstractConnectionMiddleware;
use Doctrine\DBAL\Driver\Middleware\AbstractDriverMiddleware;
use Doctrine\DBAL\Driver\Middleware\AbstractStatementMiddleware;
use Doctrine\DBAL\Driver\Result;
use Doctrine\DBAL\Driver\Statement;

class QueryMiddleware implements Middleware
{
    private $platform;

    // The Platform is asked for so it is built before the first query.
    public function __construct(?Platform $platform = null)
    {
        $this->platform = $platform;
    }

    public function wrap(Driver $driver): Driver
    {
        return new QueryDriver($driver);
    }
}

class QueryDriver extends AbstractDriverMiddleware
{
    // The database from the connection's driver name (pdo_mysql, pgsql...).
    public function connect(array $params): DriverConnection
    {
        $db = Queries::databaseOfDriver(isset($params['driver']) ? $params['driver'] : '');
        return new QueryConnection(parent::connect($params), $db);
    }
}

class QueryConnection extends AbstractConnectionMiddleware
{
    private $db;

    public function __construct(DriverConnection $connection, $db)
    {
        parent::__construct($connection);
        $this->db = $db;
    }

    public function prepare(string $sql): Statement
    {
        return new QueryStatement(parent::prepare($sql), $sql, $this->db);
    }

    public function query(string $sql): Result
    {
        return Queries::timed($this->db, $sql, function () use ($sql) {
            return parent::query($sql);
        });
    }

    // int, not DBAL 4's int|string: narrower, so it fits both versions.
    public function exec(string $sql): int
    {
        return Queries::timed($this->db, $sql, function () use ($sql) {
            return parent::exec($sql);
        });
    }
}

class QueryStatement extends AbstractStatementMiddleware
{
    private $sql;
    private $db;

    public function __construct(Statement $statement, $sql, $db)
    {
        parent::__construct($statement);
        $this->sql = $sql;
        $this->db = $db;
    }

    // DBAL 3 passes $params (deprecated), DBAL 4 nothing: handed on as given.
    public function execute($params = null): Result
    {
        $args = func_get_args();
        return Queries::timed($this->db, $this->sql, function () use ($args) {
            return parent::execute(...$args);
        });
    }
}
