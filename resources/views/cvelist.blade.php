@extends('layouts.app')
@section('csslinks')
@endsection
@section('style')
@endsection
@section('content')



<div style="width:90%;" class="container-fluid">
	<h5>{{$component->component_name}} <small>{{$component->version}}</small></h5>
	<small>
		<div style="margin-top:-10px;">
			<a style="float:left;" href="{{$component->url}}">{{$component->vendor}}</a>
			<!-- <div style="margin-top:-10px;">{{$component->cpe_name}}<small></div>-->
			<a style="margin-left:10px;" href="www.google.com" class="badge badge-pill badge-info">SVM Notifications&nbsp{{count($component->notifications)}}</a>
		</div>
	</small>
	<div style="margin-top:20px;" id="table"></div>
</div>
@endsection
@section('script')
var cves=@json($cves);

$(document).ready(function()
{
	console.log("Loading CVE List Page");
	var table = new Tabulator("#table", {
		data:cves,
		layout:"fitDataFill",
		tooltips:true,
		//autoColumns:true,
		columns:
		[
			{title:"Id", field:"cve",
				mutator:function(value, data, type, params, component)
				{
					console.log(data);
					cve = data.cve.CVE_data_meta.ID;
					if(data.impact.baseMetricV3 === undefined)
					{
						data.baseMetricVersion = 2; 
						data.baseScore = data.impact.baseMetricV2.cvssV2.baseScore;
						data.baseSeverity = data.impact.baseMetricV2.cvssV2.baseSeverity;
						data.vectorString = data.impact.baseMetricV2.cvssV2.vectorString;
					}
					else
					{
						data.baseMetricVersion = 3; 
						data.baseScore = data.impact.baseMetricV3.cvssV3.baseScore;
						data.baseSeverity = data.impact.baseMetricV3.cvssV3.baseSeverity;
						data.vectorString = data.impact.baseMetricV3.cvssV3.vectorString;
					}
					
					data.publishedDate = new Date(data.publishedDate.$date.$numberLong*1).toISOString().slice(0,10);
					data.lastModifiedDate = new Date(data.lastModifiedDate.$date.$numberLong*1).toISOString().slice(0,10);
					if(data.other.Debian[cve].fixed !== undefined)
					{
						var result = [];
						j=0;
						for (var i in data.other.Debian[cve].fixed)
							result[j++] = i;
						data.fixedin = result.join("\r\n");
					}
					else
						data.fixedin = [];
					data.debianbug = '';
					if(data.other.Debian[cve].debianbug !== undefined)
					{
						data.debianbug = data.other.Debian[cve].debianbug;
						console.log(data.debianbug);
					}
					return data.cve.CVE_data_meta.ID;
				}, 
				formatter:
				function(cell, formatterParams, onRendered)
				{
					return '<a href="https://nvd.nist.gov/vuln/detail/'+cell.getValue()+'">'+cell.getValue()+'</a>';
				}
			},
			{title:"Id", field:"baseMetricVersion"},
			{title:"Id", field:"baseScore"},
			{title:"Id", field:"baseSeverity", formatter:
				function(cell, formatterParams, onRendered)
				{
					if(cell.getValue()=='CRITICAL')
						return '<span class="badge badge-pill badge-danger">CRITICAL</span>';
					else if(cell.getValue()=='HIGH')
						return '<span class="badge badge-pill badge-warning">HIGH</span>';
					else
						return '<span class="badge badge-pill badge-Light">'+cell.getValue()+'</span>';
				}
			},
			{title:"Id", field:"vectorString"},
			{title:"Published", field:"publishedDate",formatter:
				function(cell, formatterParams, onRendered)
				{
					value =  new Date(cell.getValue()).toString().substring(0, 15);
					d1 = new Date(cell.getValue());
					d2 = new Date();
					days = dates.daysBetween(d1,d2);
					if(days <= 31)
						return '<span style="color:green;font-weight:bold">'+value+'</span>';
					return '<span>'+value+'</span>';
					
				}
			},
			{title:"Last Update", field:"lastModifiedDate",formatter:
				function(cell, formatterParams, onRendered)
				{
					value =  new Date(cell.getValue()).toString().substring(0, 15);
					d1 = new Date(cell.getValue());
					d2 = new Date();
					days = dates.daysBetween(d1,d2);
					if(days <= 31)
						return '<span style="color:green;font-weight:bold">'+value+'</span>';
					return '<span>'+value+'</span>';
					
				}
			},
			{title:"Debian Fixed",field:"fixedin", formatter:
				function(cell, formatterParams, onRendered)
				{
					versions  = cell.getValue();
					data = cell.getRow().getData();
					cve = data.cve;
					if(versions.length==0)
						return '<a href="https://security-tracker.debian.org/tracker/'+cve+'">'+'Not Fixed'+'</a>';
					
					versions = versions.split("\r\n");
					return '<a href="https://security-tracker.debian.org/tracker/'+cve+'">'+versions[0]+'</a>';
				}
			},
			{title:"Debian Defect",field:"debianbug", formatter:
				function(cell, formatterParams, onRendered)
				{
					if(cell.getValue() > 0) 
						return '<a href="https://bugs.debian.org/'+cell.getValue()+'">'+cell.getValue()+'</a>';
					return cell.getValue();
				}
			}
		]
	});
	table.hideColumn("debianbug");
})
@endsection
