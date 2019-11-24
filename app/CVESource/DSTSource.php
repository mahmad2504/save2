<?php
namespace App\CVESource;

use \MongoDB\Client;
use MongoDB\BSON\UTCDateTime;
use App\Utility\Utility;

class DSTSource implements CVESourceInterface
{
	private  $dsturl =  null;
	private  $datafolder = null;
	private  $db=null;
	private  $filename =null;
	private  $collection;
	private  $retdata = null;
	private $aliases= [
		/*'golang-1.11'=>'golang:go',
		'golang-1.12'=>'golang:go',
		'golang-1.13'=>'golang:go',
		'golang-1.7'=>'golang:go',
		'golang-1.8'=>'golang:go',
		'golang'=>'golang:go',
		'golang-go.net-dev'=>'golang:go',
		'golang-golang-x-net-dev'=>'golang:go',

		'golang-github-docker-docker-credential-helpers'=>'docker:credential_helpers',
		'golang-github-go-ldap-ldap'=>'go-ldap_project:ldap',
		'golang-github-seccomp-libseccomp-golang'=>'libseccomp-golang',
		'golang-go.crypto'=>'golang:crypto',

		'golang-github-appc-docker2aci'=>'docker2aci',
		'golang-github-miekg-dns'=>'miekg-dns',
		'file'=>'file_project:file',
		'wpa' =>'hostapd',*/
	];
	function __construct()
	{
		ini_set("memory_limit","3000M");
		set_time_limit(2000);

		$dbname = config('database.connections.mongodb.database');
		$collectionname = config('app.dst.collection');
		$this->filename = config('app.dst.filename');
		$this->dsturl = config('app.dst.url');
		$this->datafolder = config('app.datafolder')."/dst";

		$mongoClient=new Client("mongodb://".config('database.connections.mongodb.host'));
		$this->db = $mongoClient->$dbname;
		$this->collection = $this->db->$collectionname;


		if(!file_exists($this->datafolder))
            mkdir($this->datafolder, 0, true);
	}
	function Update($rebuild=0)
	{
		Utility::Console(time(),"Checking Debiam Tracker Data feed"); 
        $contentsize = Utility::GetContentSize($this->dsturl);
		$filename = $this->datafolder."/".$this->filename;
		$oldcontentsize = 0;
        if(file_exists($filename))
        {
            $oldcontentsize = filesize($filename);
        }
        $update = false;
        if(($oldcontentsize!=$contentsize)||($rebuild==1))
		{
			$this->Download($this->dsturl);
            $update = true;
            Utility::Console(time(),'Downloaded');
		}			
		if($update) 
		{
			Utility::Console(time(),"Updating cve database"); 
            $this->UpdateDatabase();
            Utility::Console(time(),'Imported Debian Security Tracker Data successfull');
        }
        else
            Utility::Console(time(),'Updated');
	}    
    private function Download($url)
	{
		$ch = curl_init(); 
		Utility::Console(time(),'Downloading '.basename($url));

		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);

		//curl_setopt($ch, CURLOPT_SSLVERSION,3);
		$data = curl_exec ($ch);
		$error = curl_error($ch); 
		
		curl_close ($ch);
		$file = fopen($this->datafolder."/".$this->filename, "w");
		fputs($file, $data);
		fclose($file);
	}
	private function CreateIndexes()
	{
		Utility::Console(time(),"Updating Search Indexes"); 
		$this->collection->createIndex(["package"=>'text']);
		$this->collection->createIndex(["cve"=>1]);	
	}
	private function UpdateDatabase()
	{
		$this->collection->Drop();
		$data = $this->PreProcess($this->datafolder."/".$this->filename);
		$this->collection->insertMany($data);	
		$this->CreateIndexes();
		//Create Text Index
		//$this->collection->createIndex(["configurations.nodes.cpe_match.cpe23Uri"=>'text',"configurations.nodes.children.cpe_match.cpe23Uri"=>'text']);
		//Create Index
		//$this->collection->createIndex(["cve.CVE_data_meta.ID"=>1]);
	}
	private function  PreProcess($filename)
	{
        $array = [];
		$data = json_decode(file_get_contents($filename));
		foreach($data as $package=>$object)
		{

			foreach($object as $cve=>$d)
			{
				$o = new \StdClass();
				$o->cve = $cve;
				$o->package = $package;
				$o->data = $d;
				$array[] = $o;
			}
		}

		Utility::Console(time(),"Updating ".$filename." data in database"); 
		return $array;	
	}
	function GetPackageList()
	{
		$cursor = $this->collection->distinct('package');
		$alias_packages = [];
		$packages_to_remove = [];
		for($i=0;$i<count($cursor);$i++)
		{
			$package = $cursor[$i];
			if(isset($this->aliases[$package]))
			{
				$alias_packages[$this->aliases[$package]] = $this->aliases[$package];
				$packages_to_remove[] = $i;
			}
		}
		foreach($packages_to_remove as $i)
		{
			unset($cursor[$i]);
		}
		foreach($alias_packages as $alias)
		{
			$cursor[] = $alias;
		}
		sort($cursor);
		$cursor = array_unique($cursor);
		
		//$cursor = $this->collection->distinct('package');
		return $cursor;
	}
	public function GetCVEDetail($cve)
	{
		if(is_array($cve))
			$query = ['cve' => ['$in' => $cves]];
		else
			$query = ['cve'=>$cve];
		
		$cursor = $this->collection->find($query);
		$dataarray = [];
		foreach($cursor as $cve)
		{
			//dd($cve);
			$data = new \StdClass();
			//$data->cve = $cve->cve;
			//$data->releases = $cve->data->releases;
			foreach($cve->data->releases as $name=>$release)
			{
				if($release->status == 'resolved')
					$data->fixed[$release->fixed_version] = 1;	
				
				
			}
			$data->package = $cve->package;
			if(isset($cve->data->debianbug))
			{
				$data->debianbug =  $cve->data->debianbug;
			}
			else
				$data->debianbug = '';
			$dataarray[$cve->cve] =$data;
		}
		return $dataarray;
	}
	public function GetCVEs($package,$version=null)
	{
		return $this->GetPackage($package);
	}
	private function GetPackage($package,$firscall=1)
	{
		if($firscall)
			$this->retdata = array();

		if( in_array($package,$this->aliases))
		{
			$searchdata = '';
			foreach($this->aliases as $opackage=>$alias)
			{
				if($alias == $package )
					$this->GetPackage($opackage,0);
			}
		}
		else
		{
			$searchdata = '"'.$package.'"';
			$query = ['$text' => ['$search' => $searchdata]];
			$cursor = $this->collection->find(['package'=>$package]);
			//dd($cursor->toArray());
			$this->retdata[] = $cursor;
			//$cursor = $this->collection->find($query,['package']);
		}
		if($firscall)
		{
			$dataarray = [];
			foreach($this->retdata as $record)
			{
				foreach($record as $cve)
				{
					$data = new \StdClass();
					$data->package_found = $cve->package;
					//$data->cve = $cve->cve;
					//$data->releases = $cve->data->releases;
					foreach($cve->data->releases as $name=>$release)
					{
						if($release->status == 'resolved')
						{
							//dd($release->repositories);
							foreach($release->repositories as $release=>$version)
								$data->fixed[$version] = 1;	
						}
						else
						{
							foreach($release->repositories as $release=>$version)
								$data->fixed[$version] = 0;	
						}
						if(isset($release->fixed_version))
						{
							$data->fixed[$version] = 1;	
						}
					}
					$dataarray[$cve->cve] =$data;
				}
			}
			return $dataarray;
		}
	}
}