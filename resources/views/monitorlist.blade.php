@extends('layouts.app')
@section('csslinks')
@endsection
@section('style')
@endsection
@section('content')
<div style="width:90%;" class="container-fluid">
	<div id="table"></div>
</div>
@endsection
@section('script')
var list=@json($list);
//console.log(list);
$(document).ready(function()
{
	console.log("Loading Home Page");
	var table = new Tabulator("#table", {
		data:list,
		layout:"fitDataFill",
		tooltips:true,
		//autoColumns:true,
		columns:
		[
			{title:"Id", field:"id"},
			{title:"Vendor", field:"vendor",
				formatter:
				function(cell, formatterParams, onRendered)
				{
					if(cell.getValue().length > 40)
						return cell.getValue().slice(0,40)+"...";
					return cell.getValue();
				}
			
			},
			{title:"Component", field:"component_name",
				formatter:
				function(cell, formatterParams, onRendered)
				{
					if(cell.getValue().length > 40)
						return cell.getValue().slice(0,40)+"...";
					return cell.getValue();
				}
			},
			{title:"Version", field:"version"},
			{title:"CVE", field:"cve",mutator:
				function(value, data, type, params, component)
				{
					data.cve_count = value.length;
					return value;
				}
			},
			{title:"CVE", field:"cve_count",sorter:"number",tooltip:false,
				formatter:
				function(cell, formatterParams, onRendered)
				{
					data = cell.getRow().getData();
					title = data.cve.join(',');
					//console.log(data.cve);
					if(cell.getValue() == 0)
						return '';
					return '<small><span title="'+title+'" class="badge badge-pill badge-warning">'+cell.getValue()+' CVE</span></small>';
					return  cell.getValue(); //return the contents of the cell;
				}
			},
			{title:"Notifications", field:"notifications",mutator:
				function(value, data, type, params, component)
				{
				
					data.notification_count = value.length;
					d1 = null;
					for(i=0;i<value.length;i++)
					{
						console.log(value[i]);
						if(value[i].last_update == null)
						{
							if(value[i].publish_date == null)
								continue;
							else
								d1 = new Date(value[i].publish_date);
						}
						if(d1==null)
						{
							d1 = new Date(value[i].last_update);
						}
						else
						{
							d2 = new Date(value[i].last_update);
							if(dates.compare(d1,d2)==-1) //d1<d2
								d1 = d2;
						}
						
					}
					//console.log(d1);
					if(d1 == '' || d1 == null)
						return null;
					data.last_update = d1.toISOString().slice(0,10);
					//data.last_update = d1.toString().substring(0, 15) ;
					return value;
				}
			},
			{title:"Notifications", field:"notification_count",
				formatter:
				function(cell, formatterParams, onRendered)
				{
					if(cell.getValue() == 0)
						return '';
					return '<small><span class="badge badge-pill badge-info">'+cell.getValue()+' Notifications</span></small>';
					return  cell.getValue(); //return the contents of the cell;
				}
			},
			{title:"Last Update", field:"last_update",
				formatter:
				function(cell, formatterParams, onRendered)
				{
					value =  new Date(cell.getValue()).toString().substring(0, 15);
					if(value == 'Invalid Date')
						return '';
					
					d1 = new Date(cell.getValue());
					d2 = new Date();
					days = dates.daysBetween(d1,d2);
					if(days <= 31)
						return '<small style="color:green;font-weight:bold">'+value+'</small>';
					return '<small>'+value+'</small>';
				}
			}
		],
		rowClick:function(e, row)
		{
			//e - the click event object
			//row - row component
			console.log("Click");
		},
		initialSort:[
			{column:"last_update", dir:"desc"}, //sort by this first
		]
	});
	table.hideColumn("notifications");
	table.hideColumn("cve");
	console.log(list);
})
@endsection
