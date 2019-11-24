<?php
namespace App;
class SVM
{
	private $url;
	private $data_folder;
	function __construct()
	{
		$this->url = config('app.svm_url');
		$this->data_folder = config('app.datafolder')."/svm/";
	}
	public function GetList($id)
	{
		
		$path=$this->data_folder.$id."/components_cve.json";
		if(!file_exists($path))
			return null;
		$list = json_decode(file_get_contents($path),true);
		return $list;
	}
	public function Sync($monitorin_list_id)
	{
		$notifications = $this->GetAllNotifications($monitorin_list_id);
		$components = $this->GetComponents($monitorin_list_id);
		foreach($components as $component)
		{
			foreach($component->notifications as $notification)
			{
				//dump($notification->id);
				if(array_key_exists($notification->id,$notifications))
				{
				}
				else
				{
					dump($notification->id);
					exit();
				}
			}
		}
		foreach($notifications as $notification)
		{
			$found = 0;
			foreach($notification->assigned_components as $componentid)
			{
				
				if(array_key_exists($componentid,$components))
				{
					$component = $components[$componentid];
					//$components[$componentid]->fromnotifications[$notification->id] = $notification; 
					foreach($component->notifications as $cnotification)
					{
						if($cnotification->id == $notification->id)
							$cnotification->data = $notification;
					}
					
					//dump($componentid);
					$found=1;
				}
				
			}
			if($found==0)
			{
				dump($notification);
				exit();
			}
		}
		//dump($components);
		foreach($components as $component)
		{
			$component->cve = [];
			foreach($component->notifications as $notification)
			{
				foreach($notification->data->cve_references as $cve)
				{
					$cve = 'CVE-'.$cve->year."-".$cve->number;
					$component->cve[$cve] = $cve;
				}
			}
			$component->cve = array_values($component->cve);
		}
		$folder = $this->data_folder.$monitorin_list_id;
		if (!file_exists($folder))
		{
			mkdir($folder, 0777, true);
		}
		$filename = $folder.'/components_cve.json';
		$old_content = '';
		if(file_exists($filename))
			$old_content = md5(file_get_contents($filename));
		$new_content = md5(json_encode($components));
		if($old_content != $new_content)
		{
			file_put_contents($filename ,json_encode($components));
		}
		return $components;
	}

//echo getContentBycURL('https://svm.cert.siemens.com/portal/api/v1/public/components/10374');
//echo getContentBycURL('https://svm.cert.siemens.com/portal/api/v1/public/components/10374/notifications');
//echo getContentBycURL('https://svm.cert.siemens.com/portal/api/v1/public/notifications/32792');
//echo getContentBycURL('https://svm.cert.siemens.com/portal/api/v1/public/notifications/48274');
//echo getContentBycURL('https://svm.cert.siemens.com/portal/api/v1/common/monitoring_lists/24A891CF/notifications');
//echo getContentBycURL('https://svm.cert.siemens.com/portal/api/v1/public/components/19683');
// Monitoring List - 24A891CF
	
	function GetAllNotifications($monitoring_list_id)
	{
		$folder = $this->data_folder.$monitoring_list_id;
		
		if (!file_exists($folder))
		{
			mkdir($folder, 0777, true);
		}

		$filename = $folder.'/notifications.json';
		$data = [];
		if(file_exists($filename ))
		{
			$data = (array) json_decode(file_get_contents($filename ));
			
		}
		$notifications = $this->getContentBycURL($this->url.'/common/monitoring_lists/'.$monitoring_list_id.'/notifications');	
		foreach($notifications as $notification)
		{
			if(array_key_exists($notification->id,$data))
			{
				$data[$notification->id]->valid = 0;
				$notificatin_data = $data[$notification->id];
				if($notification->last_update != $notificatin_data->last_update)
				{
					$detail = $this->getContentBycURL($this->url.'/public/notifications/'.$notification->id);
					$detail->valid=1;
					$detail->id = $notification->id;
					$data[$notification->id] = $detail;
				}
			}
			else
			{
				$detail = $this->getContentBycURL($this->url.'/public/notifications/'.$notification->id);
				$detail->valid=1;
				$detail->id = $notification->id;
				$data[$notification->id] = $detail;	
			}
		}
		$data_str = json_encode($data);
		file_put_contents($filename ,$data_str);
		return $data;
	}
	function GetNotifications($component_id)
	{
		$notifications =  $this->getContentBycURL($this->url.'/public/components/'.$component_id.'/notifications');
		return $notifications;
	}
	function GetComponentDetails($component_id)
	{
		$data = $this->getContentBycURL($this->url.'/public/components/'.$component_id);	
		return $data;
	}
	function GetComponents($monitoring_list_id)
	{
		$folder = $this->data_folder.$monitoring_list_id;
		
		if (!file_exists($folder))
		{
			mkdir($folder, 0777, true);
		}

		$filename = $folder.'/components.json';
		$data = [];
		if(file_exists($filename ))
		{
			$data = (array) json_decode(file_get_contents($filename ));
			
		}
		$components =  $this->getContentBycURL($this->url.'/common/monitoring_lists/'.$monitoring_list_id.'/components');
		foreach($components as $componentid)
		{
			if(!array_key_exists($componentid,$data))
			{	
				$component = GetComponentDetails($componentid);
				$notifications = GetNotifications($componentid);
				$component->id = $componentid;
				$component->notifications = $notifications;
				$component->valid = 1;
				$data[$componentid] = $component;
			}
			else 
				$data[$componentid]->valid = 0;
			
		}
		$data_str = json_encode($data);
		file_put_contents($filename ,$data_str);
		return $data;
	}
	function getContentBycURL($strURL)
	{
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_HEADER, 0);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1); // Return data inplace of echoing on screen
		curl_setopt($ch, CURLOPT_URL, $strURL);
		curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0); // Skip SSL Verification
		curl_setopt($ch, CURLOPT_SSLCERT, getcwd() . "/Z003UJ3F_cert.pem");
		curl_setopt($ch, CURLOPT_SSLKEY, getcwd() . "/Z003UJ3F_key.pem");
		//curl_setopt($ch, CURLOPT_CAINFO, "/etc/ssl/certs/ca-certificates.crt");
		
		$rsData = curl_exec($ch);
		$error = curl_error($ch);
		if($error != null)
		{
			echo $error;
			return [];
		}
		$data = json_decode($rsData);
		
		if(isset($data->errors))
		{
			dump(json_encode($data->errors));
			return [];
		}
		
		curl_close($ch);
		return $data;
	}
}