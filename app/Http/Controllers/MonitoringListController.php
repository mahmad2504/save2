<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Redirect,Response;
use \MongoDB\Client;
use App\svm;
class MonitoringListController extends Controller
{
	function __construct()
	{
		$mongoClient=new Client("mongodb://".config('database.connections.mongodb.host'));
		$dbname = config('database.connections.mongodb.database');
		$this->db = $mongoClient->$dbname;
	}
	public function Show($monitoringlist_id)
	{
		//$query = ['$text' => ['$search' => $searchdata]];
		$projection = ['projection'=>[
			'_id'=>0,
			'id'=>1,
			'vendor'=>1,
			'component_name' => 1,
			'version' => 1,
			'cve' =>1,
			'notifications.last_update' => 1,
			'notifications.publish_date' =>1,
			'notifications.data' => 1,
		]];
		//$projection=[];
		$cursor = $this->db->$monitoringlist_id->find([],$projection);
		$list = $cursor->toArray();
		//dd($list[0]);
		return view('monitorlist',compact('list','monitoringlist_id'));
		
	}
	public function Sync($monitoringlist_id)
	{
		$svm = new SVM();
		set_time_limit(0);
		$components = $svm->Sync($monitoringlist_id);
	}
	public function Import($monitoringlist_id)
	{
		$svm = new SVM();
		$list = $svm->GetList($monitoringlist_id);
		if($list == null)
			abort(403, 'Not Found');
		
		
		$list = array_values($list);
		//dd($list);
		$this->db->$monitoringlist_id->drop();
		$this->db->$monitoringlist_id->insertMany($list);	
		echo "Done";
	}	
}
