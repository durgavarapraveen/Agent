from typing import List, Dict
from core.domain.asset import DataObject
import logging

logger = logging.getLogger(__name__)

class ObjectInventory:
    def __init__(self):
        # Maps object_id -> DataObject
        self.objects: Dict[str, DataObject] = {}
        # Maps endpoint_id -> List of object_ids exposed/used
        self.by_endpoint: Dict[str, List[str]] = {}
        
    def add_object(self, obj: DataObject, endpoint_id: str = None):
        self.objects[obj.object_id] = obj
        
        if endpoint_id:
            if endpoint_id not in self.by_endpoint:
                self.by_endpoint[endpoint_id] = []
            if obj.object_id not in self.by_endpoint[endpoint_id]:
                self.by_endpoint[endpoint_id].append(obj.object_id)
                
    def get_object_identifiers(self) -> List[str]:
        return list(self.objects.keys())
        
    def get_objects_by_endpoint(self, endpoint_id: str) -> List[DataObject]:
        obj_ids = self.by_endpoint.get(endpoint_id, [])
        return [self.objects[oid] for oid in obj_ids if oid in self.objects]
