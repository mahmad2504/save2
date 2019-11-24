<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Redirect,Response;
use \MongoDB\Client;
use App\Utility\Utility;
use App\Http\Controllers\CVESourceController;

class CVEListController extends Controller
{
	function __construct()
	{
		$mongoClient=new Client("mongodb://".config('database.connections.mongodb.host'));
		$dbname = config('database.connections.mongodb.database');
		$this->db = $mongoClient->$dbname;
	}
	public function Show($monitoringlist_id,$component_id)
	{
		//dd($component_id);
		$query = ['id' => (int)$component_id];
		$projection = ['projection'=>[
			'_id'=>0,
			'id'=>1,
			'url'=>1,
			'cpe_name'=>1,
			'vendor'=>1,
			'component_name' => 1,
			'version' => 1,
			'cve' =>1,
			'notifications.last_update' => 1,
			'notifications.publish_date' =>1,
			'notifications.data' => 1,
		]];
		//$projection=[];
		$cursor = $this->db->$monitoringlist_id->find($query,$projection);
		//dd($cursor->toArray());
		$components = $cursor->toArray();
		$component = null;
		$cves = [];
		if(count($components)>0)
		{
			$component = $components[0];
			$CVECntl  = new CVESourceController();
			$cves = $CVECntl->GetCVEDetails($components[0]->cve);
		}
		//dd($component);
		return view('cvelist',compact('cves','component'));
	}
}
