from rest_framework import serializers


class DetectorSerializer(
    serializers.Serializer,
):
	type = serializers.CharField(
		required=True,
	)

	def update(self, instance, validated_data):
		instance.type = validated_data.get("detector_type", instance.type)
		return instance

	def create(self, validated_data):
		instance = Detector()
		instance.type = validated_data["type"]
		return instance
