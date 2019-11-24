<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Utility\Utility;
use MongoDB\Client;
use MongoDB\BSON\UTCDateTime;
use App\CVESource\DSTSource;
use App\CVESource\NVDSource;
class CVESourceController extends Controller
{
	private $dst = null;
	private $source = null;
	private $sources = ['Debian'=>'DSTSource'];
	private $nvd = null;
	function __construct()
	{

		$this->nvd = new NVDSource();

		/*if($request->source == 'dst')
		{
			$this->source = new DSTSource();
		}
		else if($request->source == 'nvd')
		{
			$this->source = new NVDSource();
		}
		else
			dd("Source ".$request->source." not found");*/
	}
	function GetSource($name)
	{
		$class = "App\\CVESource\\".$name;
		$class = new \ReflectionClass($class);
		return  $class->newInstanceArgs();
	}
	function Update(Request $request,$rebuild=0,$debug=0)
	{
		ini_set("memory_limit","3256M");
		set_time_limit(2000);

		if($debug == 0)
		{
        	header('Content-Type: text/event-stream');
			header('Cache-Control: no-cache');
		}

		if($request->source != null)
		{
			foreach($this->sources as $sourcename=>$sourceclass)
			{
				if($sourcename == $request->source)
				{
					$source = $this->GetSource($sourceclass);
					$source->Update($rebuild);
					return;
				}
			}
			dd("Source not dounf");
		}

		$this->nvd->Update($rebuild);
		foreach($this->sources as $source=>$class)
		{
			$source = $this->GetSource($class);
			$source->Update($rebuild,$debug);
		}
		//$this->DumpPackageList($rebuild);
	}
	public function GetCVEDetails($cves)//array
	{
		$nvdcves = $this->nvd->GetCVEDetail($cves);
		foreach($nvdcves as $nvdcve)
		{
			$cve = $nvdcve->cve->CVE_data_meta->ID;
			foreach($this->sources as $source=>$class)
			{
				$data = $this->GetSource($class)->GetCVEDetail($cve);
				if(count($data)>0)
				{
					$nvdcve->other[$source] = $data;
				}
			}
		}
		return $nvdcves;
	}
	function GetCVEs($package,$version=null,$debrev=null)
	{
		$nvdcves = $this->nvd->GetCVEs($package,$version);
		$debversion = $version.'-'.$debrev;
		foreach($nvdcves as $cve=>$detail)
		{
			foreach($this->sources as $source=>$class)
			{
				$data = $this->GetSource($class)->GetCVEDetail($cve);
				if(count($data)>0)
				{
					$nvdcves[$cve]->other[$source] = $data;
					//dd($data);
					$nvdcves[$cve]->status = 'UNKNOWN';
				}
			}
		}
		$sourcecves = [];
		
		foreach($this->sources as $source=>$class)
		{
			$sourcecves = $this->GetSource($class)->GetCVEs($package,$version);
			foreach($sourcecves as $scve=>$data)
			{
				if($version==null)
				{
					if(!isset($nvdcves[$scve]))
					{
						$nvdcves[$scve] = new \StdClass();
						$nvdcves[$scve]->cve = $scve;
					}
					$nvdcves[$scve]->other[$source] = $data;
					$nvdcves[$scve]->status = 'UNKNOWN';
					//$data->status = 'UNKNOWN';
				}
			}
		}
		
		return $nvdcves;
	}
	function GetPackageVersions($package)
	{
		$versions = $this->nvd->GetVersions($package);
		
		//function GetCVEs($package);
		//$versions = ['1.0.1','1.0.2','1.0.3'];

		return $versions;
	}
	function GetPackageList()
	{
		$datafolder = config('app.datafolder')."/packages";
		$filename_valid = $datafolder."/valid.json";
		if(\file_exists($filename_valid))
			$goodpackages = json_decode(file_get_contents($filename_valid));
		else
			return [];
		
		return $goodpackages;
	}
	function DumpPackageList($rebuild=0)
	{
		Utility::Console(time(),"Dumping  Package List"); 
		$goodpackages = [];
		$badpackages = [];
		$datafolder = config('app.datafolder')."/packages";
		if(!file_exists($datafolder))
			mkdir($datafolder, 0, true);

		$filename_valid = $datafolder."/valid.json";
		$filename_invalid = $datafolder."/invalid.json";
		
		if($rebuild == 0)
		{
			if(\file_exists($filename_valid))
				$goodpackages = json_decode(file_get_contents($filename_valid));
			if(\file_exists($filename_invalid))
				$badpackages = json_decode(file_get_contents($filename_invalid));
		}
		
		$dst =  new DSTSource();
        $nvd =  new NVDSource();
		$packages = $dst->GetPackageList();
		$i=0;
		
        foreach($packages as $package)
        {
			if(in_array($package,$goodpackages))
			{
				continue;
			}
			if(in_array($package,$badpackages))
			{
				continue;
			}
			Utility::Console(time(),"Checking ".$package); 
            $cves = $nvd->GetCVEs($package);
            if(count($cves) == 0)
            {
				//$info = $dst->GetPackage($package);
				$badpackages[] = $package;
            }
            else
            {
                $goodpackages[] = $package;
            }
            //ConsoleLog::Msg(time(),$package);
		}
	

		$goodpackages = json_encode($goodpackages);
		$file = fopen($filename_valid, "w");
		fputs($file, $goodpackages);
		fclose($file);
		
		$badpackages = json_encode($badpackages);
		$file = fopen($filename_invalid, "w");
		fputs($file, $badpackages);
		fclose($file);
		
		Utility::Console(time(),"Done"); 
		//return $goodpackages;
	}
}
/*
class DSTController extends Controller
{
	private  $dsturl =  null;
	private  $datafolder = null;
	private  $db=null;
	private  $filename =null;
	private  $collection;
	function __construct()
	{
		$dbname = config('database.connections.mongodb.database');
		$collectionname = config('app.dst.collection');
		$this->filename = config('app.dst.filename');
		$this->dsturl = config('app.dst.url');
		$this->datafolder = config('app.datafolder');

		$mongoClient=new Client();
		$this->db = $mongoClient->$dbname;
		$this->collection = $this->db->$collectionname;


		if(!file_exists($this->datafolder))
            mkdir($this->datafolder, 0, true);
	}
	function UpdateNVD(Request $request)
	{
		ini_set("memory_limit","3256M");
		set_time_limit(2000);

		if($request->debug == null)
		{
        	header('Content-Type: text/event-stream');
			header('Cache-Control: no-cache');
		}
		$update = false;
        if(!file_exists($this->datafolder."/".$this->filename)||($request->rebuild==1))
		{
			$this->Download($this->dsturl);
			$update = true;
		}		
		Utility::ConsoleLog(time(),'Downloaded');
	
		//if($update) 
		{
			Utility::ConsoleLog(time(),"Updating cve database"); 
			$this->UpdateDatabase();
		}
		Utility::ConsoleLog(time(),'Imported NVD Database successfull');
	
	}    
	
    private function Download($url)
	{
		$ch = curl_init(); 
		Utility::ConsoleLog(time(),'Downloading '.basename($url));
		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		//curl_setopt($ch, CURLOPT_SSLVERSION,3);
		$data = curl_exec ($ch);
		$error = curl_error($ch); 
		curl_close ($ch);
		$file = fopen($this->datafolder."/".$this->filename, "w");
		fputs($file, $data);
		fclose($file);
	}
	private function UpdateDatabase()
	{
		$this->collection->Drop();
		$data = $this->PreProcess($this->datafolder."/".$this->filename);
		$this->collection->insertMany($data);	
		$this->collection->createIndex(["package"=>'text']);
		//Create Index
		$this->collection->createIndex(["cve"=>1]);	
		Utility::ConsoleLog(time(),"Updating Search Indexes"); 
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

		Utility::ConsoleLog(time(),"Updating ".$filename." data in database"); 
		return $array;	
	}
	function PackageInfo(Request $request,$packagename) 
	{
		
		$info=DST::where('package', $packagename)->get();
		foreach($info as $i)
		{
			//echo $i->cve;
			//dd($i->data['releases']);
			//foreach($i->data['releases'] as $release)
			//{
		//		var_dump($release);
		//	}
		}
	}
	
	function PackageList()
	{
		$packages = DST::orderBy('package','desc')->get(['package','cve'])->unique('package');
		//dd(count($packages));
		//$packages = DST::where('package','LIKE', '%' . $value . '%')->orderBy('package', 'ASC')->get(['package']);
		//$packages = $packages->unique('package');

		return view('test', compact('users'));
		//return $packages;
	}
}
*/