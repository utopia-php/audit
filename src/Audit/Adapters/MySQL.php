<?php

namespace Utopia\Audit\Adapters;

use Utopia\Audit\Adapter;
use PDO;

class MySQL extends Adapter
{
    /**
     * @var PDO
     */
    protected $pdo;

    /**
     * @param PDO $pdo
     */
    public function __construct(PDO $pdo)
    {
        $this->pdo = $pdo;
    }

    /**
     * Log.
     *
     * Add specific event log
     *
     * @param string $userId
     * @param string $event
     * @param string $resource
     * @param string $userAgent
     * @param string $ip
     * @param string $location
     * @param array  $data
     *
     * @return bool
     *
     * @throws \Exception
     */
    public function log(string $userId, string $event, string $resource, string $userAgent, string $ip, string $location, array $data):bool
    {
        $st = $this->getPDO()->prepare('INSERT INTO `'.$this->getNamespace().'.audit.audit`
            SET userId = :userId, event= :event, resource= :resource, userAgent = :userAgent, ip = :ip, location = :location, time = "'.\date('Y-m-d H:i:s').'", data = :data
		');

        $data = \mb_strcut(\json_encode($data), 0, 64000, 'UTF-8'); // Limit data to MySQL 64kb limit

        $st->bindValue(':userId', $userId, PDO::PARAM_STR);
        $st->bindValue(':event', $event, PDO::PARAM_STR);
        $st->bindValue(':resource', $resource, PDO::PARAM_STR);
        $st->bindValue(':userAgent', $userAgent, PDO::PARAM_STR);
        $st->bindValue(':ip', $ip, PDO::PARAM_STR);
        $st->bindValue(':location', $location, PDO::PARAM_STR);
        $st->bindValue(':data', $data, PDO::PARAM_STR);

        $response = $st->execute();

        return $response == true ;
    }

    public function getLogsByUser(string $userId):array
    {
        $st = $this->getPDO()->prepare('SELECT *
        FROM `'.$this->getNamespace().'.audit.audit`
            WHERE userId = :userId
            ORDER BY `time` DESC LIMIT 10
        ');

        $st->bindValue(':userId', $userId, PDO::PARAM_STR);

        $st->execute();

        return $st->fetchAll();
    }

    public function getLogsByResource(string $resource): array
    {
        $st = $this->getPDO()->prepare('SELECT *
        FROM `'.$this->getNamespace().'.audit.audit`
            WHERE resource = :resource
            ORDER BY `time` DESC LIMIT 10
        ');

        $st->bindValue(':resource', $resource, PDO::PARAM_STR);

        $st->execute();

        return $st->fetchAll();
    }

    public function getLogsByUserAndActions(string $userId, array $actions):array
    {
        $query = [];

        foreach ($actions as $k => $id) {
            $query[] = ':action_'.$k;
        }

        $query = \implode(',', $query);

        $st = $this->getPDO()->prepare('SELECT *
        FROM `'.$this->getNamespace().'.audit.audit`
            WHERE `event` IN ('.$query.')
                AND userId = :userId
            ORDER BY `time` DESC LIMIT 10
        ');

        $st->bindValue(':userId', $userId, PDO::PARAM_STR);

        foreach ($actions as $k => $id) {
            $st->bindValue(':action_'.$k, $id);
        }

        $st->execute();

        return $st->fetchAll();
    }

    /**
     * Delete logs older than $seconds seconds
     * 
     * @param int $seconds 
     * 
     * @return bool   
     */
    public function cleanup(int $seconds):bool
    {
        $st = $this->getPDO()->prepare('DELETE 
        FROM `'.$this->getNamespace().'.audit.audit`
            WHERE (UNIX_TIMESTAMP(NOW()) - UNIX_TIMESTAMP(`time`)) >  :seconds');

        $st->bindValue(':seconds', $seconds, PDO::PARAM_INT);
        $response = $st->execute();

        return $response == true;
    }

    /**
     * @return PDO
     */
    protected function getPDO()
    {
        return $this->pdo;
    }
}
