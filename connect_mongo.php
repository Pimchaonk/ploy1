
<?php
    require 'vendor/autoload.php';

    $user = "bpt-testlog";
    $pwd = "g7ZmSrfzLqNrVhcXmuopY5SfxZvBFVB7ZDXpEfDtSE0dZlLs0Y9bsDqTYDdd0ZtBmV3tSnQpxLotACDbKrIy1A";

    $mongoclient = new MongoDB\Client(
        'mongodb://${user}:${pwd}@bpt-testlog.mongo.cosmos.azure.com/:10255'
    );
?>