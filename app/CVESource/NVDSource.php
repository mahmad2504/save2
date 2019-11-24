<?php

namespace App\CVESource;

use \MongoDB\Client;
use MongoDB\BSON\UTCDateTime;
use App\Utility\Utility;


class NVDSource implements CVESourceInterface
{
	private  $nvdurls =  null;
	private  $datafolder = null;
	private  $db =  null;
	private  $collection =  null;
	private  $cpe_collection = null;
	private  $aliases= [
		/*'389-admin' => ['389_administration_server'],
		'389-ds-base' => ['389_directory_server'],
		'ack-grep' => ['ack'],
		'advi' => ['camimages','camlimages'],
		'aolserver4' => ['aolserver'],
		'archvsync'=>['ftpsync'],
		'argyll'=>['argyllcms'],
		'arj'=>['arj_archiver'],
		'atril'=>['evince'],
		'automake-1.14'=>['automake'],
		'automake-1.15'=>['automake'],
		'automake1.11'=>['automake'],
		'bcron'=>['bcron_exec'],
		'bind9'=>['bind'],
		'botan1.10'=>['botan'],
		'bsh'=>['beanshell'],
		'bwa'=>['burrow-wheeler_aligner_project'],
		'clutter-1.0'=>['clutter'],
		'cyrus-imapd-2.4'=>['cyrus-imapd'],
		'db5.3'=>['db'],
		'gcc-7'=>['gcc'],
		'gcc-6'=>['gcc'],
		'gcc-8'=>['gcc'],
		'chromium-browser'=>['chrome'],
		'dhcpcd5'=>['dhcpcd'],
		'wpa' =>['hostapd']*/
	];
	function __construct()
	{
		ini_set("memory_limit","8000M");
		set_time_limit(2000);

		$dbname = config('database.connections.mongodb.database');
		$collectionname = config('app.nvd.collection');
		$this->nvdurls = config('app.nvd.urls');
		$this->cpeurl = config('app.cpe.url');
		$cpe_collectionname = config('app.cpe.collection');
		$this->datafolder = config('app.datafolder')."/nvd";
		$mongoClient=new Client("mongodb://".config('database.connections.mongodb.host'));
		$this->db = $mongoClient->$dbname;
		$this->collection = $this->db->$collectionname;
		$this->cpe_collection = $this->db->$cpe_collectionname;
		if(!file_exists($this->datafolder))
            mkdir($this->datafolder, 0, true);
	}
	public function Update($rebuild=0)
	{
		$updatecvedb = false;
		//$this->nvdurls = [];
        foreach($this->nvdurls as $nvdurl)
		{
			Utility::Console(time(),"Checking ".basename($nvdurl)." feed"); 
			$contentsize = Utility::GetContentSize($nvdurl);
			$filename = basename($nvdurl);
			$filename = $this->datafolder."/".$filename;
			$oldcontentsize = 0;
			if(file_exists($filename))
			{
				$oldcontentsize = filesize($filename);
			}
			
			if(($oldcontentsize!=$contentsize)||($rebuild==1))
			{
				$this->Download($nvdurl,$filename);
				$updatecvedb = true;
			}
			else
				Utility::Console(time(),"Updated"); 	
		}
		Utility::Console(time(),'Downloaded');
	
		if($updatecvedb)
		{
			Utility::Console(time(),"Updating cve database"); 
			$this->UpdateDatabase();
			Utility::Console(time(),'Imported NVD Data successfull');
		}
		else
		   Utility::Console(time(),'NVD Data already uptodate');

		$cpeurl = $this->cpeurl;
		Utility::Console(time(),"Checking ".basename($cpeurl)." feed"); 
		$contentsize = Utility::GetContentSize($cpeurl);
		$filename = basename($cpeurl);
		$filename = $this->datafolder."/".$filename;
		$oldcontentsize = 0;
		$updatecpedb = false;
		if(file_exists($filename))
		{
			$oldcontentsize = filesize($filename);
		}	
		if(($oldcontentsize!=$contentsize)||($rebuild==1))
		{
			$this->Download($cpeurl,$filename);
			$updatecpedb = true;
		}
		else
			Utility::Console(time(),"Updated"); 
		//ConsoleLog::Msg(time(),'Downloaded');
	
		if($updatecpedb)
		{
			Utility::Console(time(),"Updating cpe database"); 
			$this->UpdateCPEDatabase();
			Utility::Console(time(),'Imported CPE Data successfull');
		}
		else
			Utility::Console(time(),'CPE Data already uptodate');

		
    }    
    private function Download($url,$filename)
	{
		$zip = new \ZipArchive;
		$ch = curl_init(); 
		Utility::Console(time(),'Downloading '.basename($url));
		curl_setopt($ch, CURLOPT_URL, $url);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		//curl_setopt($ch, CURLOPT_SSLVERSION,3);
		$data = curl_exec ($ch);
		$error = curl_error($ch); 
		curl_close ($ch);

		$file = fopen($filename, "w");
		fputs($file, $data);
		fclose($file);
		//SendConsole(time(),'Unzipping '); 
		if ($zip->open($filename ) === TRUE) 
		{
			$zip->extractTo($this->datafolder."/");
			$zip->close();
			//SendConsole(time(),'Done '.basename($url) ); 
		} 
		else 
		{
            Utility::Console(time(),'Failed '.basename($url));
		}	
	}
	
	private function UpdateCPEDatabase()
	{
		$this->cpe_collection->Drop();
		$cpeurl = $this->cpeurl;
		$filename = str_replace('.zip','',basename($cpeurl));
		$json = json_decode(file_get_contents($this->datafolder."/".$filename));
		$vendors = [];
		$objects= [];
		$count= 0;
		for($i=0;$i<count($json->matches);$i++)
		{
			$d[] = $json->matches[$i];
			$count++;
			//if($count>100)
			 // break;
			foreach($json->matches[$i]->cpe_name as $cpe_name)
			{	
				//if($count == 1000)
				//	dd($cpe_name->cpe23Uri);
				$cpe_array = explode(":",$cpe_name->cpe23Uri);
				
				$cpepart = $cpe_array[2];
				$cpevendor = $cpe_array[3];
				$cpeproduct = $cpe_array[4];
				$cpeversion = $cpe_array[5];
				$cpeupdate =  $cpe_array[6];
				$obj = null;
				if(!array_key_exists($cpevendor,$vendors))
				{
					$obj = new \StdClass();
					$obj->vendor = $cpevendor;
					$obj->product = $cpeproduct;
					$obj->version = $cpeversion;
			
					$vendors[$cpevendor] = [];
					$vendors[$cpevendor][$cpeproduct]=[];
					$vendors[$cpevendor][$cpeproduct][$cpeversion]=$obj;
				}
				else
				{
					if(!array_key_exists($cpeproduct,$vendors[$cpevendor]))
					{
						$obj = new \StdClass();
						$obj->vendor = $cpevendor;
						$obj->product = $cpeproduct;
						$obj->version = $cpeversion;
						
						$vendors[$cpevendor][$cpeproduct]=[];
						$vendors[$cpevendor][$cpeproduct][$cpeversion]=$obj;
					}
					else
					{
						if(!array_key_exists($cpeversion,$vendors[$cpevendor][$cpeproduct]))
						{
							$obj = new \StdClass();
							$obj->vendor = $cpevendor;
							$obj->product = $cpeproduct;
							$obj->version = $cpeversion;
						
							$vendors[$cpevendor][$cpeproduct]=[];
							$vendors[$cpevendor][$cpeproduct][$cpeversion]=$obj;
						}
					}
				}
				if($obj != null)
					$objects[] = $obj;
				$count++;
				//dd($cpe_array);
			}
		}
		
		//dd($json.matches);
		//dd($objects);
		//$objects = json_decode(json_encode($objects));
		//dd($objects);
		$this->cpe_collection->insertMany($objects);	
		$this->cpe_collection->createIndex(["product"=>'text']);
		echo $filename;
	} 
	private function UpdateDatabase()
	{

		$this->collection->Drop();
	
		foreach($this->nvdurls as $nvdurl)
		{
			$filename = str_replace('.zip','',basename($nvdurl));
			$data = $this->PreProcess($this->datafolder."/".$filename);

			//echo $filename." ".$this->db;
			$this->collection->insertMany($data);		
		}
		Utility::Console(time(),"Updating Search Indexes"); 
		//Create Text Index
		$this->collection->createIndex(["configurations.nodes.cpe_match.cpe23Uri"=>'text',"configurations.nodes.children.cpe_match.cpe23Uri"=>'text']);
		//Create Index
		$this->collection->createIndex(["cve.CVE_data_meta.ID"=>1]);
	}
	private function  PreProcess($filename)
	{
		$json = json_decode(file_get_contents($filename));
		
		foreach($json->CVE_Items as $cve)
		{
			$date = new \DateTime($cve->publishedDate);
			$date->setTime(0,0,0);
			$ts = $date->getTimestamp();
			$cve->publishedDate = new UTCDateTime($ts*1000);
		
			$date = new \DateTime($cve->lastModifiedDate);
			$date->setTime(0,0,0);
			$ts = $date->getTimestamp();
			$cve->lastModifiedDate = new UTCDateTime($ts*1000);
			//$cve->publishedDate = new MongoDB\BSON\Timestamp(1, $ts);
			//echo $date->__toString();
			//echo $cve->publishedDate;
			//exit();
		}
		Utility::Console(time(),"Updating ".$filename." data in database"); 
		return $json->CVE_Items;	
	}
	public function GetCveOfPackage($package)
	{
		$searchdata = '';
		if(isset($this->aliases[$package]))
		{
			foreach($this->aliases[$package] as $alias)
			{
				$searchdata .= $alias." ";	
			}
		}
		else
			$searchdata = '"'.$package.'"';
	
		//dd($searchdata);
		//$searchdata = 'camimages camlimages';
		//echo $searchdata;
		$query = ['$text' => ['$search' => $searchdata]];
		
		$cursor = $this->collection->find($query,['projection'=>['cve.CVE_data_meta.ID'=>1]]);
		$cvelist = [];
		foreach($cursor->toArray() as $cve)
		{
			$cvelist[] = $cve->cve->CVE_data_meta->ID; 
		}
		return $cvelist;
	}
	public function GetVersions($package)
	{
		$query = ['$text' => ['$search' => $package]];
		$cursor = $this->cpe_collection->find($query);
		//dd($cursor->toArray());
		$versions = [];
		foreach($cursor as $cpe)
		{
			//echo($cpe->cpe23Uri)."\n";
			$cpe_array = explode(":",$cpe->cpe23Uri);
			$cpepart = $cpe_array[2];
			$cpevendor = $cpe_array[3];
			$cpeproduct = $cpe_array[4];
			$cpeversion = $cpe_array[5];
			$cpeupdate =  $cpe_array[6];
			if($cpeproduct==$package)
			{
				//$cpeversion = $cpeversion.":".$cpeupdate;
				if(($cpeversion != '*')&&($cpeversion != '-'))
					$versions[$cpeversion] = $cpeversion;
				if(isset($cpe->versionEndExcluding))
					$versions[$cpeversion] = $cpe->versionEndExcluding;
				if(isset($cpe->versionEndIncluding))
					$versions[$cpeversion] = $cpe->versionEndIncluding;
				if(isset($cpe->versionStartIncluding))
					$versions[$cpeversion] = $cpe->versionStartIncluding;
				if(isset($cpe->versionStartExcluding))
					$versions[$cpeversion] = $cpe->versionStartExcluding;
					
			}
			foreach($cpe->cpe_name as $cpe)
			{
				$cpe_array = explode(":",$cpe->cpe23Uri);
				$cpepart = $cpe_array[2];
				$cpevendor = $cpe_array[3];
				$cpeproduct = $cpe_array[4];
				$cpeversion = $cpe_array[5];
				$cpeupdate =  $cpe_array[6];
				if($cpeproduct==$package)
				{
					//$cpeversion = $cpeversion.":".$cpeupdate;
					if(($cpeversion != '*')&&($cpeversion != '-'))
						$versions[$cpeversion] = $cpeversion;
					if(isset($cpe->versionEndExcluding))
						$versions[$cpeversion] = $cpe->versionEndExcluding;
					if(isset($cpe->versionEndIncluding))
						$versions[$cpeversion] = $cpe->versionEndIncluding;
					if(isset($cpe->versionStartIncluding))
						$versions[$cpeversion] = $cpe->versionStartIncluding;
					if(isset($cpe->versionStartExcluding))
						$versions[$cpeversion] = $cpe->versionStartExcluding;
				}
			}
			//dd($cpeversion);
		}
		return array_values($versions);
	}
	public function GetCVEDetail($cves)
	{
		$query = ['cve.CVE_data_meta.ID' => ['$in' => $cves]];
		$projection = ['projection'=>[
			'cve.CVE_data_meta.ID'=>1,
			//'configurations'=>1,
			'impact'=>1,
			'publishedDate'=>1,
			'lastModifiedDate'=>1
		]];
		//$projection = [];
		$cursor = $this->collection->find($query,$projection);
		$list = $cursor->toArray();
		return $list;
	}
	
	public function GetCVEs($package,$version=null)
	{
		
		$aliases = [];
		$cves = $this->GetCveOfPackage($package);
	
		//$cves = $this->GetPackage($package);
		$query = ['cve.CVE_data_meta.ID' => ['$in' => $cves]];
		$cursor = $this->collection->find($query,['projection'=>['cve.CVE_data_meta.ID'=>1,'configurations'=>1,'impact'=>1]]);
		$data_array =  array();
		foreach($cursor as $cve)
		{
			$data = new \StdClass();
			$data->cve = $cve->cve->CVE_data_meta->ID;
			if(isset($cve->impact->baseMetricV3))
			{
				$data->cvssVersion = 3.0;
				$data->baseScore = $cve->impact->baseMetricV3->cvssV3->baseScore;
				$data->baseSeverity = $cve->impact->baseMetricV3->cvssV3->baseSeverity;
			}
			else
			{
				$data->cvssVersion = 2.0;
				$data->baseScore = $cve->impact->baseMetricV2->cvssV2->baseScore;
				$data->baseSeverity = $cve->impact->baseMetricV2->severity;
			}
			
			$data->type = $this->DetermineVulType($cve,$package,$version,$aliases);
			if($data->type == null)
				continue;
			
			//if($data->type->version_match != '')
			if($version == null)
				$data_array[$data->cve] = $data;
			else
			{
				if($data->type->version_match != '')
					$data_array[$data->cve] = $data;
			}
		}
		//dd($data_array);
		return $data_array;
		//$query = ['$text' => ['$search' => $searchdata]];
		//$cursor = $this->collection->find($query,['configurations','cve.CVE_data_meta.ID','impact']);

	}
	public function GetPackageList()
	{
		
	}
	//function GetCVEs($packagename)
	//{
	//	echo	\DSTServices::GetCVEs('ffff');//DSTServices::CVEs('FFF');
		//$t = new DSTCVEInformation();
	//	$searchdata = '"'.$packagename.'" ';
	//	$query = ['$text' => ['$search' => $searchdata]];
//		$cursor = $this->collection->find($query,['cve.CVE_data_meta.ID']);
		//return $cursor->toArray();
//	}
	private function ProcessImpactNode($cpe_match,$package,$version,$obj,$aliases)
	{
		foreach($cpe_match as $cpe)
		{
			if($cpe->vulnerable == true)
			{
				$cpe_array = explode(":",$cpe->cpe23Uri);
				$cpepart = $cpe_array[2];
				$cpevendor = $cpe_array[3];
				$cpeproduct = $cpe_array[4];
				$cpeversion = $cpe_array[5];
				$cpeupdate =  $cpe_array[6];
				
				//echo "-->".$cpevendor." ".$cpeproduct." ".$package."<br>";
				/*var_dump($package);
				var_dump($cpeproduct);
				var_dump($aliases);*/
				
				if(($package==$cpevendor)||($package == $cpeproduct)||in_array($cpeproduct, $aliases))
				{
					$failed = 0;
					$passed = 0;
					$matched_versions = '';
					$rangecheckpresent = 0;
					$obj->vendor_match  = $cpevendor;
					$obj->package_match = $cpeproduct;
					$obj->version_found = $cpeversion;
					//var_dump($cpe);
					if(isset($cpe->versionStartExcluding))
					{
						$rangecheckpresent = 1;
						$obj->version_found = 'versionStartExcluding:'.$cpe->versionStartExcluding;
						if($this->version_compare2($version,$cpe->versionStartExcluding)>0)
						{
							$matched_versions = 'versionStartExcluding:'.$cpe->versionStartExcluding;
							//echo "First\r\n";
							$passed++;
						}
						else
							$failed++;
					}
					if(isset($cpe->versionStartIncluding))
					{
						$rangecheckpresent = 1;
						$obj->version_found = 'versionStartIncluding:'.$cpe->versionStartIncluding;
						if( ($this->version_compare2($version,$cpe->versionStartIncluding)==0)||
							($this->version_compare2($version,$cpe->versionStartIncluding)>0))
						{
							$matched_versions = 'versionStartIncluding:'.$cpe->versionStartIncluding;
							//echo "Second\r\n";
							$passed++;
						}
						else
							$failed++;
					}
					if(isset($cpe->versionEndExcluding))
					{
						$rangecheckpresent = 1;
						$obj->version_found = 'versionEndExcluding:'.$cpe->versionEndExcluding;
						//echo "-".$version."-".$cpe->versionEndExcluding."-<br>";
						//echo $this->version_compare2($version,$cpe->versionEndExcluding)."<br>";
						//echo version_compare($version,$cpe->versionEndExcluding)."<br>";
						
						if($this->version_compare2($version,$cpe->versionEndExcluding)<0)
						{
							$matched_versions = 'versionEndExcluding:'.$cpe->versionEndExcluding;
							//echo "Third\r\n";
							$passed++;
						}
						else
							$failed++;
					}
					if(isset($cpe->versionEndIncluding))
					{
						$flag=0;
						//echo $version."--".$cpe->versionEndIncluding."<br>"; 
						//if('1.30' == $cpe->versionEndIncluding)
						//	$flag=1;
						$rangecheckpresent = 1;
						$obj->version_found = 'versionEndIncluding:'.$cpe->versionEndIncluding;
						$check = $this->version_compare2($version,$cpe->versionEndIncluding,$flag);

						if(($check==0)|| ($check<0))
						{
							$matched_versions = 'versionEndIncluding:'.$cpe->versionEndIncluding;
							//echo " Fourth\r\n";
							$passed++;
						}
						else
						{
							//echo " Failed ".$check."\r\n";
							$failed++;
						}
						//if($flag == 1)
						//	dd("break");
					}
					//echo "===========>".$failed." ".$passed." ".$version."<br>";
					
					if($failed > 0)
					{
						$obj->package_match = $cpeproduct;
						$obj->version_match = '';
						//return $obj;
					}
					else if($passed > 0)
					{
						$obj->package_match = $cpeproduct;
						$obj->version_match = $matched_versions;
						return $obj;
					}
					if($rangecheckpresent == 0)
					{
						if($this->version_compare2($version,$cpeversion)==0)
						{
							$obj->package_match = $cpeproduct;
							$obj->version_match = $cpe->cpe23Uri;
							//$cpe->cpe23Uri
							return $obj;
						}
						if($cpeversion == '*')
						{		
							$obj->package_match = $cpeproduct;
							$obj->version_match = '*';
							//$cpe->cpe23Uri
							return $obj;
						}
						if($cpeversion == '-')
						{
							
							$obj->package_match = $cpeproduct;
							//$obj->version_match = '-';
							//$cpe->cpe23Uri
							//return $obj;
						}
					}
					//$obj->package_match = $cpeproduct;
					//$obj->version_match = '';
					//dvultype.package = 'MATCH';
					//dvultype.version = 'NOT_MATCH;
					//if($obj->version_match != '')
					//	return $obj;
				}
			}
		}
		return $obj;
	}
	private function DetermineVulType($cve,$packagename,$versionnumber,$aliases)
	{
		
		$obj = new \StdClass();
		$obj->vendor_match = '';
		$obj->package_match = '';
		$obj->version_match = '';
		$debug=0;
		
		//if($cve->cve->CVE_data_meta->ID == 'CVE-2009-2044')
		//	dd($cve);
		for($i=0;$i < count($cve->configurations->nodes);$i++)
		{
			//if($cve->cve->CVE_data_meta->ID == 'CVE-2009-2044')
			//	dd( $cve->configurations->nodes[$i]);

			$node = $cve->configurations->nodes[$i];
			
			if($node->operator == 'OR')
			{
				$obj = $this->ProcessImpactNode($node->cpe_match,$packagename,$versionnumber,$obj,$aliases);
				if($obj->version_match != '')
					return $obj;
			}
			else if($node->operator == 'AND')
			{
				if(isset($node->cpe_match))
				{
					$obj = $this->ProcessImpactNode($node->cpe_match,$packagename,$versionnumber,$obj,$aliases);
					if($obj->version_match != '')
						return $obj;
				}
				else
				{
					for($j=0;$j<count($node->children);$j++)
					{
						if(isset($node->children[$j]->cpe_match))
						{
							$obj = $this->ProcessImpactNode($node->children[$j]->cpe_match,$packagename,$versionnumber,$obj,$aliases);
							if($obj->version_match != '')
								return $obj;
						}
					}
				}
			}
		}
		if($obj->vendor_match=='' and $obj->package_match=='')
			return null;
		return $obj;
	}	
	function version_compare2($a, $b,$debug=0) 
	{ 
		
		$msg = "Comparing ".$a." with ".$b;
		//echo $msg;
		//SendConsole(time(),$msg); 
		//$a = explode(".", str_replace(".0",'',$a)); //Split version into pieces and remove trailing .0 
		//$b = explode(".", str_replace(".0",'',$b)); //Split version into pieces and remove trailing .0 
	
		$a = explode(".", str_replace(".0",'',$a)); //Split version into pieces and remove trailing .0 
		$b = explode(".", str_replace(".0",'',$b)); //Split version into pieces and remove trailing .0 

		//$a = explode(".", rtrim($a, ".0")); //Split version into pieces and remove trailing .0 
		//$b = explode(".", rtrim($b, ".0")); //Split version into pieces and remove trailing .0 
		//if($debug)
		//	dd($b);
		//dd($b);
		//SendConsole(time(),print_r($a)."--".print_r($b)); 
						
		foreach ($a as $depth => $aVal) 
		{ //Iterate over each piece of A 
			$aVal = trim($aVal);
			if (isset($b[$depth])) 
			{ //If B matches A to this depth, compare the values 
				$b[$depth] = trim($b[$depth]);
				if ($aVal > $b[$depth]) 
				{
					//echo "[".$aVal."]".">"."[".$b[$depth]."]\r\n";
					//echo gettype($aVal).">".gettype($b[$depth])."\r\n";
					return 1; //Return A > B 
				}
				else if ($aVal < $b[$depth]) return -1; //Return B > A 
				//An equal result is inconclusive at this point 
			} 
			else 
			{ //If B does not match A to this depth, then A comes after B in sort order 
	
				return 1; //so return A > B 
			} 
		} 
		//At this point, we know that to the depth that A and B extend to, they are equivalent. 
		//Either the loop ended because A is shorter than B, or both are equal. 
		return (count($a) < count($b)) ? -1 : 0; 
	} 
}